/**
 * Identity setup tools — the conversational onboarding flow:
 *   auth_status       inspect mode, login state, pinned workload identities
 *   auth_login        OAuth browser flow (zero-config) or token-file instructions
 *   auth_use_identity pick an agent identity per workspace, pin a scoped
 *                     bridge token (value stored 0600, never shown)
 *   auth_logout       revoke pinned bridge tokens, wipe the session
 *
 * The bridge installs with NO credential. After auth_use_identity, one
 * install serves all projects: per-call context selects the workspace,
 * and the pinned identity for that workspace supplies the scope triple.
 */

import { z } from 'zod';
import type { CallCtx } from '../resolver/index.js';
import { callControl, resolverBaseUrl } from '../resolver/index.js';
import { resolveServer } from '../auth/cliFiles.js';
import { fail, ok, type ToolResult } from '../resolver/types.js';
import { withContext } from './common.js';
import { needJwt } from '../resolver/guards.js';
import { loadSession, saveSession } from '../auth/session.js';
import { discoverEndpoints, startLogin, OAuthNotAvailable, type PendingLogin } from '../auth/oauth.js';
import { fetchAgents, pinBridgeIdentity } from './agents.js';

export const authStatusSchema = z.object({});
export type AuthStatusArgs = z.infer<typeof authStatusSchema>;

export const authLoginSchema = z.object({
  mode: z.enum(['oauth', 'token-file']).optional().describe('oauth: browser flow (default, tries OAuth then falls back to instructions). token-file: terminal export instructions only.'),
});
export type AuthLoginArgs = z.infer<typeof authLoginSchema>;

export const authLogoutSchema = z.object({
  revoke: z.boolean().default(true).describe('Also revoke pinned bridge tokens server-side (best-effort, needs login)'),
});
export type AuthLogoutArgs = z.infer<typeof authLogoutSchema>;

export const authUseIdentitySchema = z.object({
  agent: z.string().optional().describe('Agent name or registration ID. Omit to list candidates / use the single one.'),
  workspace: z.string().optional().describe('Workspace name or ID (defaults to current/pinned/single)'),
  environment: z.string().optional().describe('Environment scope for the issued token (defaults to active)'),
  label: z.string().optional().describe('Token label (default "mcp-bridge")'),
});
export type AuthUseIdentityArgs = z.infer<typeof authUseIdentitySchema>;

let pendingLogin: PendingLogin | null = null;

export async function authStatus(call: CallCtx, _args: AuthStatusArgs): Promise<ToolResult> {
  const session = loadSession();
  const identities = Object.entries(session.identities).map(([wsId, pin]) => ({
    workspace_id: wsId,
    agent: pin.agent_name,
    registration_id: pin.registration_id,
    scope: { project_id: pin.project_id, environment: pin.environment },
    resolve_may_be_empty: pin.resolve_may_be_empty === true,
    pinned_at: pin.pinned_at,
  }));
  const hasJwt = !!call.creds.token;
  const hasWorkload = !!call.creds.agentToken;
  let next: string;
  if (call.mode.mode === 'local' && call.mode.binary) {
    next = hasWorkload
      ? 'Local mode active via the CLI keychain session; management + credentialed calls ready.'
      : 'Local mode active via the CLI keychain session — tools work with no further setup. Call auth_use_identity only if you need cloud-resolver calls without the CLI.';
  } else if (!hasJwt && !hasWorkload) {
    next = 'Call auth_login to connect (OAuth browser flow, no credentials needed).';
  } else if (!hasWorkload) {
    next = 'Logged in for management. Call auth_use_identity to pin a workload identity for credentialed calls.';
  } else if (call.creds.tokenKind === 'jwt') {
    next = 'Fully connected: management + credentialed calls.';
  } else {
    next = 'Workload identity present (credentialed calls only). Call auth_login for management tools.';
  }
  return ok({
    mode: call.mode.mode,
    binary: call.mode.binary,
    management_login: call.creds.token
      ? { present: true, kind: call.creds.tokenKind, source: call.creds.tokenSource }
      : { present: false },
    workload_identity: call.creds.agentToken
      ? { present: true, pinned_workspaces: identities.length }
      : { present: false },
    identities,
    oauth: session.oauth ? { linked: true } : { linked: false },
    workspace_key: { present: call.creds.workspaceKey !== null },
    control_plane: call.server.url,
    cloud_resolver: resolverBaseUrl(),
    context: {
      project: call.ctx.project?.projectName ?? null,
      workspace: call.ctx.project?.workspaceName ?? null,
      environment: call.ctx.env.name,
    },
    next,
  });
}

export async function authLogin(call: CallCtx, args: AuthLoginArgs): Promise<ToolResult> {
  if (args.mode === 'token-file') return ok(tokenFileInstructions());
  try {
    const control = resolveServer(call.ctx.cwd);
    const endpoints = await discoverEndpoints(control.url);
    pendingLogin?.cancel();
    const pending = await startLogin(endpoints);
    pendingLogin = pending;
    void pending.done.then((bundle) => {
      const session = loadSession();
      saveSession({
        ...session,
        oauth: {
          access_token: bundle.access_token,
          refresh_token: bundle.refresh_token,
          expires_at: bundle.expires_at,
          token_url: endpoints.token,
          client_id: 'agentsecrets-mcp',
        },
      });
      if (pendingLogin === pending) pendingLogin = null;
    });
    return ok({
      status: 'awaiting_approval',
      auth_url: pending.authUrl,
      instructions: [
        '1. Open auth_url in a browser (you, the human — not the agent).',
        '2. Approve access for "agentsecrets-mcp".',
        '3. Return here and call auth_status to verify, then auth_use_identity to pin a workload identity.',
        'The URL expires in 10 minutes; call auth_login again for a fresh one.',
      ],
    });
  } catch (e) {
    if (e instanceof OAuthNotAvailable) return ok(tokenFileInstructions(e.message));
    return fail(e instanceof Error ? e.message : String(e));
  }
}

function tokenFileInstructions(reason?: string): Record<string, unknown> {
  return {
    status: 'manual_flow',
    ...(reason ? { note: reason } : {}),
    instructions: [
      '1. In a terminal on this machine, run: agentsecrets login',
      '2. Then export the session (tokens go terminal -> file, never through chat):',
      '   agentsecrets mcp bridge auth.export > ~/.agentsecrets/mcp-token && chmod 600 ~/.agentsecrets/mcp-token',
      '3. Set AGENTSECRETS_TOKEN_FILE=$HOME/.agentsecrets/mcp-token in the MCP client env (the PATH is config; the secret is not).',
      '4. Call auth_status to verify, then auth_use_identity to pin a workload identity.',
    ],
  };
}

export async function authLogout(call: CallCtx, args: AuthLogoutArgs): Promise<ToolResult> {
  const revoke = args.revoke ?? true;
  const session = loadSession();
  const revoked: string[] = [];
  if (revoke && call.creds.token && call.creds.tokenKind === 'jwt') {
    const ctl = callControl(call);
    for (const [wsId, pin] of Object.entries(session.identities)) {
      try {
        const tokens = (await ctl.get('agents.token_list', {
          workspace_id: wsId,
          registration_id: pin.registration_id,
        })) as Array<Record<string, unknown>>;
        for (const t of tokens ?? []) {
          if (t['status'] === 'active' && t['label'] === pin.label && typeof t['id'] === 'string') {
            await ctl.del('agents.token_revoke', {
              workspace_id: wsId,
              registration_id: pin.registration_id,
              token_id: t['id'],
            });
            revoked.push(`${pin.agent_name}:${String(t['id'])}`);
          }
        }
      } catch {
        /* best effort per identity */
      }
    }
  }
  saveSession({ oauth: null, identities: {}, defaults: { workspace_id: null, project_id: null, project_name: null } });
  return ok({
    status: 'logged_out',
    revoked_bridge_tokens: revoked,
    note: revoke
      ? 'Session wiped; bridge-issued tokens revoked where the login permitted.'
      : 'Session wiped locally; pinned tokens left valid server-side (revoke via control plane if needed).',
  });
}

export async function authUseIdentity(call: CallCtx, args: AuthUseIdentityArgs): Promise<ToolResult> {
  if (call.mode.mode === 'local') {
    return fail('Local mode uses the CLI keychain session directly — no identity pinning needed. This tool is for cloud mode.');
  }
  try {
    needJwt(call.creds);
  } catch (e) {
    return fail(`${e instanceof Error ? e.message : String(e)} Call auth_login first.`);
  }
  const ctl = callControl(call);
  // Resolve workspace: explicit > pinned default > single available.
  let workspaceId = args.workspace ?? loadSession().defaults.workspace_id ?? call.ctx.project?.workspaceId ?? null;
  if (!workspaceId) {
    const list = ((await ctl.get('workspaces.list')) as Array<{ id: string; name: string }>) ?? [];
    if (list.length === 1 && list[0]) workspaceId = list[0].id;
    else {
      return fail(
        `Multiple workspaces available — pass {workspace} explicitly: ${(list ?? []).map((w) => w.name).join(', ') || '(none found)'}.`
      );
    }
  } else {
    // Allow names.
    try {
      const list = ((await ctl.get('workspaces.list')) as Array<{ id: string; name: string }>) ?? [];
      const hit = list.find((w) => w.id === workspaceId || w.name === workspaceId);
      if (hit) workspaceId = hit.id;
    } catch {
      /* use as-is */
    }
  }
  const ws = workspaceId as string;
  const agents = await fetchAgents(call, ws);
  if (agents.length === 0) {
    return fail('No agent identities in this workspace. Create one in the control plane (Agents → Register), then call auth_use_identity again.');
  }
  let picked = args.agent ? agents.find((a) => a.id === args.agent || a.name === args.agent) ?? null : null;
  if (args.agent && !picked) {
    return fail(`Agent ${JSON.stringify(args.agent)} not found. Available: ${agents.map((a) => a.name).join(', ')}.`);
  }
  if (!picked) {
    if (agents.length === 1 && agents[0]) {
      picked = agents[0];
    } else {
      // Picker: return candidates with scopes for the human to choose.
      return ok({
        status: 'choose_identity',
        workspace_id: ws,
        candidates: agents.map((a) => ({
          agent: a.name,
          registration_id: a.id,
          scope: { project_id: a.project_id ?? '(workspace-wide — reaches every project; pass {project} to target one)' },
        })),
        instructions: 'Ask the human which agent identity to use, then call auth_use_identity again with {agent}.',
      });
    }
  }
  const reg = picked;
  const environment = args.environment ?? call.ctx.env.name;
  const issued = (await ctl.post(
    'agents.token_issue',
    { environment, label: args.label ?? 'mcp-bridge' },
    { workspace_id: ws, registration_id: reg.id }
  )) as { token_id: string; token: string; label?: string; expires_at?: string };
  if (!issued.token) return fail('Server did not return a token value.');
  const { pin, replaced } = await pinBridgeIdentity(call, ws, reg, issued.token, issued.label ?? args.label ?? 'mcp-bridge', environment);
  const session = loadSession();
  saveSession({ ...session, defaults: { workspace_id: ws, project_id: reg.project_id, project_name: null } });
  void replaced;
  return withContext(call, {
    status: 'identity_pinned',
    agent: reg.name,
    registration_id: reg.id,
    scope: { workspace_id: ws, project_id: pin.project_id, environment: pin.environment },
    ...(pin.resolve_may_be_empty
      ? { warning: 'This registration is workspace-wide (no project): cloud resolve reaches every project in the workspace. Pass {project} on proxy_call to target one project explicitly.' }
      : {}),
    setup: 'complete — proxy_call and management tools now work for this workspace. Repeat per workspace as needed.',
  });
}

export const authDescriptions = {
  auth_status:
    'CALL THIS FIRST, before any other tool. Reports: how this server connects (local app vs cloud), ' +
    'what logins exist, which agent identities are pinned (with their exact scope), and the single next step to get connected. Takes no inputs.',
  auth_login:
    'Connect with zero pre-configuration. Returns a web URL for the HUMAN to open and approve (you cannot approve it yourself — present the URL and wait), ' +
    'or terminal instructions when browser login is unavailable. WHEN: auth_status says nothing is connected.',
  auth_logout:
    'Disconnect: wipes stored logins and revokes bridge-issued credentials server-side by default. ' +
    'WHEN: the human says to disconnect, or before handing a machine to someone else.',
  auth_use_identity:
    'Choose which agent identity this server acts as in a workspace: shows candidates with their exact scope, ' +
    'then mints and pins a credential for the chosen one (stored securely, value never shown). ' +
    'WHEN: auth_status asks for it, or cloud calls need a workload identity. Repeat once per workspace.',
};
