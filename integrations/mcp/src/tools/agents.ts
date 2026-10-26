/**
 * Agent identity tools. A workload credential IS an agent identity: the raw
 * token secret (verified by hash) or its agt_ identifier (verified by id
 * match) carries the exact (workspace, project, environment) triple that
 * scopes cloud-resolver secret resolution — the request itself carries
 * no scope. See auth_use_identity for how the bridge pins one identity
 * per workspace.
 *
 * Token values are NEVER returned to the model: issue/pin flows store
 * the value straight into the 0600 session file and return metadata only.
 * (Operators needing the raw value use the terminal, not the agent.)
 */

import { z } from 'zod';
import type { CallCtx } from '../resolver/index.js';
import { callControl } from '../resolver/index.js';
import { fail, type PinnedIdentity, type ToolResult } from '../resolver/types.js';
import { dispatch, resolveWorkspaceId, withContext } from './common.js';
import { needJwt } from '../resolver/guards.js';
import { loadSession, saveSession } from '../auth/session.js';

export const agentListSchema = z.object({
  workspace: z.string().optional().describe('Workspace name or ID (defaults to current context)'),
  project: z.string().optional().describe('Project name or ID — limits to project-scoped agents'),
});
export type AgentListArgs = z.infer<typeof agentListSchema>;

export const agentDeleteSchema = z.object({
  agent: z.string().describe('Agent name or registration ID (areg_...)'),
  workspace: z.string().optional(),
  confirm: z.literal(true).describe('Required: revokes all tokens and deletes the registration'),
});
export type AgentDeleteArgs = z.infer<typeof agentDeleteSchema>;

export const agentTokenIssueSchema = z.object({
  agent: z.string().describe('Agent name or registration ID (areg_...) to issue for'),
  workspace: z.string().optional(),
  label: z.string().optional().describe('Token label (default "mcp-bridge")'),
  environment: z.string().optional().describe('Environment scope (defaults to active; binds token scope)'),
  expires_in: z.string().optional().describe('TTL e.g. "30d" (server applies rotation policy caps)'),
});
export type AgentTokenIssueArgs = z.infer<typeof agentTokenIssueSchema>;

export const agentTokenRotateSchema = z.object({
  agent: z.string().describe('Agent name or registration ID (areg_...) the token belongs to'),
  token_id: z.string().describe('The token ID to rotate'),
  workspace: z.string().optional(),
  compromise: z.boolean().optional().describe('true = immediate revoke of the old token (poison family); default routine (overlap)'),
  overlap_hours: z.number().int().nonnegative().optional().describe('Overlap window before the old token dies (routine only; default 24)'),
  confirm: z.literal(true).describe('Required: acknowledges this mints a new credential and may poison the old family'),
});
export type AgentTokenRotateArgs = z.infer<typeof agentTokenRotateSchema>;

export interface AgentShape {
  id: string;
  name: string;
  workspace_id: string;
  project_id: string | null;
  token_count?: number;
}

interface TokenMeta {
  id: string;
  label?: string;
  status?: string;
  created_at?: string;
  expires_at?: string | null;
  last_used_at?: string | null;
}

function safeTokenMeta(t: Record<string, unknown>): TokenMeta {
  return {
    id: String(t['id'] ?? ''),
    ...(typeof t['label'] === 'string' ? { label: t['label'] } : {}),
    ...(typeof t['status'] === 'string' ? { status: t['status'] } : {}),
    ...(typeof t['created_at'] === 'string' ? { created_at: t['created_at'] } : {}),
    ...(t['expires_at'] ? { expires_at: String(t['expires_at']) } : {}),
    ...(t['last_used_at'] ? { last_used_at: String(t['last_used_at']) } : {}),
  };
}

/** Workspace agents, project-scoped included (ListAll semantics with fallback). */
export async function fetchAgents(call: CallCtx, workspaceId: string): Promise<AgentShape[]> {
  const ctl = callControl(call);
  try {
    const list = (await ctl.get('agents.list', { workspace_id: workspaceId }, { include_projects: 'true' })) as AgentShape[];
    return list ?? [];
  } catch {
    const list = (await ctl.get('agents.list', { workspace_id: workspaceId })) as AgentShape[];
    return list ?? [];
  }
}

export async function resolveRegistration(call: CallCtx, workspaceId: string, ref: string): Promise<AgentShape> {
  const list = await fetchAgents(call, workspaceId);
  const hit = list.find((a) => a.id === ref || a.name === ref);
  if (!hit) throw new Error(`Agent ${JSON.stringify(ref)} not found in this workspace.`);
  return hit;
}

/**
 * Pin a bridge identity: revoke the previously pinned bridge token for
 * this workspace (best-effort, needs the JWT), store the new token 0600,
 * and return metadata WITHOUT the value (Omit token by construction).
 * Records the token's scope triple for call-time enforcement.
 */
export async function pinBridgeIdentity(
  call: CallCtx,
  workspaceId: string,
  reg: AgentShape,
  token: string,
  label: string,
  environment: string | null
): Promise<{ pin: Omit<PinnedIdentity, 'token'>; replaced: boolean }> {
  const session = loadSession();
  const prev = session.identities[workspaceId];
  let replaced = false;
  if (prev && prev.token !== token) {
    replaced = true;
    // Best-effort server-side revocation of the superseded bridge token.
    // Only tokens carrying our pin label are touched — never foreign tokens.
    try {
      const ctl = callControl(call);
      const tokens = (await ctl.get('agents.token_list', {
        workspace_id: workspaceId,
        registration_id: prev.registration_id,
      })) as Array<Record<string, unknown>>;
      for (const t of tokens ?? []) {
        if (t['status'] === 'active' && t['label'] === prev.label && typeof t['id'] === 'string') {
          await ctl.del('agents.token_revoke', {
            workspace_id: workspaceId,
            registration_id: prev.registration_id,
            token_id: t['id'],
          });
        }
      }
    } catch {
      /* revocation is hygiene, not correctness — the new pin still wins locally */
    }
  }
  const pin: PinnedIdentity = {
    registration_id: reg.id,
    agent_name: reg.name,
    token,
    label,
    pinned_at: new Date().toISOString(),
    workspace_id: workspaceId,
    project_id: reg.project_id ?? null,
    environment,
    scope_source: 'registration',
    ...(reg.project_id ? {} : { resolve_may_be_empty: true as const }),
  };
  const fresh = loadSession();
  saveSession({ ...fresh, identities: { ...fresh.identities, [workspaceId]: pin } });
  const { token: _dropped, ...meta } = pin;
  void _dropped;
  return { pin: meta, replaced };
}

export async function agentList(call: CallCtx, args: AgentListArgs): Promise<ToolResult> {
  return dispatch(call, 'agent.list', { ...args }, async () => {
    needJwt(call.creds);
    const workspaceId = await resolveWorkspaceId(call, args.workspace);
    const ctl = callControl(call);
    const endpoint = args.project ? 'agents.list_project' : 'agents.list';
    const params: Record<string, string> = { workspace_id: workspaceId };
    if (args.project && call.ctx.project?.projectId) params['project_id'] = call.ctx.project.projectId;
    const list = ((await ctl.get(endpoint, params)) as AgentShape[]) ?? [];
    const details = [];
    for (const ag of list) {
      let tokens: TokenMeta[] = [];
      try {
        const raw = (await ctl.get('agents.token_list', { workspace_id: workspaceId, registration_id: ag.id })) as Array<Record<string, unknown>>;
        tokens = (raw ?? []).map(safeTokenMeta);
      } catch {
        tokens = [];
      }
      details.push({ agent: ag, tokens });
    }
    return withContext(call, { workspace_id: workspaceId, agents: details });
  });
}

export async function agentDelete(call: CallCtx, args: AgentDeleteArgs): Promise<ToolResult> {
  return dispatch(call, 'agent.delete', { ...args, confirm: true }, async () => {
    needJwt(call.creds);
    const workspaceId = await resolveWorkspaceId(call, args.workspace);
    const reg = await resolveRegistration(call, workspaceId, args.agent);
    const ctl = callControl(call);
    const tokens = ((await ctl.get('agents.token_list', { workspace_id: workspaceId, registration_id: reg.id })) as Array<{ id: string; status?: string }>) ?? [];
    for (const t of tokens) {
      if (t.status === 'active') {
        await ctl.del('agents.token_revoke', { workspace_id: workspaceId, registration_id: reg.id, token_id: t.id });
      }
    }
    await ctl.del('agents.delete', { workspace_id: workspaceId, registration_id: reg.id });
    // Drop any local pin for the deleted registration.
    const session = loadSession();
    if (session.identities[workspaceId]?.registration_id === reg.id) {
      const identities = { ...session.identities };
      delete identities[workspaceId];
      saveSession({ ...session, identities });
    }
    return withContext(call, { status: 'success', agent: args.agent });
  });
}

export async function agentTokenIssue(call: CallCtx, args: AgentTokenIssueArgs): Promise<ToolResult> {
  return dispatch(call, 'agent.token_issue', { ...args }, async () => {
    needJwt(call.creds);
    const workspaceId = await resolveWorkspaceId(call, args.workspace);
    const reg = await resolveRegistration(call, workspaceId, args.agent);
    const environment = args.environment ?? call.ctx.env.name;
    const issued = (await callControl(call).post(
      'agents.token_issue',
      {
        ...(environment ? { environment } : {}),
        label: args.label ?? 'mcp-bridge',
        ...(args.expires_in ? { expires_in: args.expires_in } : {}),
      },
      { workspace_id: workspaceId, registration_id: reg.id }
    )) as { token_id: string; token: string; label?: string; expires_at?: string };
    if (!issued.token) throw new Error('Server did not return a token value.');
    await pinBridgeIdentity(call, workspaceId, reg, issued.token, issued.label ?? args.label ?? 'mcp-bridge', environment ?? null);
    return withContext(call, {
      status: 'issued_and_pinned',
      token_id: issued.token_id,
      label: issued.label ?? args.label ?? 'mcp-bridge',
      expires_at: issued.expires_at ?? null,
      scope: { workspace_id: workspaceId, project_id: reg.project_id ?? null, environment: environment ?? null },
      stored: 'pinned to this workspace in the 0600 bridge session (value never shown)',
      warning: 'The raw value was stored directly and is NOT shown. For terminal/CI use, issue via `agentsecrets` CLI instead.',
    });
  });
}

/**
 * Rotate a workload token: a new value with overlap (routine) or immediate
 * revoke of the old (compromise). Like the CLI, it requires confirm:true and
 * (server-side) the human's auth, because it mints a durable credential and in
 * compromise mode poisons the old family. The new token value is NEVER returned
 * — the human retrieves it from the terminal.
 */
export async function agentTokenRotate(call: CallCtx, args: AgentTokenRotateArgs): Promise<ToolResult> {
  return dispatch(call, 'agent.token_rotate', { ...args, confirm: true }, async () => {
    needJwt(call.creds);
    const workspaceId = await resolveWorkspaceId(call, args.workspace);
    const reg = await resolveRegistration(call, workspaceId, args.agent);
    const compromise = args.compromise ?? false;
    const overlapHours = compromise ? 0 : (args.overlap_hours ?? 24);
    const rotated = (await callControl(call).post(
      'agents.token_rotate',
      compromise ? { overlap_hours: 0, reason: 'compromise' } : { overlap_hours: overlapHours, reason: 'routine' },
      { workspace_id: workspaceId, registration_id: reg.id, token_id: args.token_id }
    )) as { token_id?: string; rotation?: { family_id?: string; overlap_until?: string } };
    return withContext(call, {
      status: 'rotated',
      agent: args.agent,
      token_id: rotated.token_id ?? args.token_id,
      family_id: rotated.rotation?.family_id ?? null,
      reason: compromise ? 'compromise' : 'routine',
      old_valid_until: rotated.rotation?.overlap_until ?? null,
      warning: 'The new token value is shown ONCE in the terminal `agent token rotate` output and is NOT returned here. Store it via the CLI if needed.',
    });
  });
}

export const agentDescriptions = {
  agent_list:
    'See registered agent identities in a workspace — named credential-holders (CI jobs, bots, other assistants) with their token metadata (label, status, expiry). ' +
    'Token values are NEVER shown. WHEN: the human asks what automatons exist, or you need an agent name for token_issue. Prefer auth_use_identity for guided setup.',
  agent_delete:
    'Revoke every token of an agent identity and delete the identity itself. ' +
    'WHEN: only on the human\u2019s explicit request (e.g. decommissioning a bot). Requires confirm:true AND human approval — this kills a live credential.',
  agent_token_issue:
    'Mint a new credential (token) for an agent identity AND pin it as this workspace\u2019s bridge identity. ' +
    'The value goes straight into secure storage and is NEVER displayed — not even to you. ' +
    'WHEN: setting up headless access, or auth_use_identity directed you here. Prefer auth_use_identity for the guided flow.',
  agent_token_rotate:
    'Rotate a workload token for an agent identity: new value with overlap (routine) or immediate revoke (compromise). ' +
    'WHEN: a token leaked (compromise) or on a routine cadence. Requires confirm:true AND the human\u2019s auth. ' +
    'The new token value is NEVER returned — the human gets it from the terminal. ' +
    'This mints a durable credential, so it is refused unless a human enabled writes in the MCP client configuration.',
};
