/**
 * Workspace tools.
 * - workspace_list works OFFLINE from the login-synced cache (mirrors the
 *   CLI); with a JWT it can also hit GET workspaces/ for fresh data.
 * - workspace_create mints a fresh 32-byte data key and sealed-boxes it to
 *   the user's public key (fetched via the public users endpoint), exactly
 *   like the Go CLI — the server requires encrypted_workspace_key.
 * - workspace_switch pins session defaults (+ CLI global config in local mode).
 */

import { z } from 'zod';
import type { CallCtx } from '../resolver/index.js';
import { callControl } from '../resolver/index.js';
import { fail, type ToolResult } from '../resolver/types.js';
import { dispatch, withContext } from './common.js';
import { needJwt } from '../resolver/guards.js';
import { generateWorkspaceKey, sealForUser } from '../crypto.js';
import { loadGlobalConfig, saveGlobalConfig } from '../auth/cliFiles.js';
import { loadSession, saveSession } from '../auth/session.js';

export const workspaceListSchema = z.object({});
export type WorkspaceListArgs = z.infer<typeof workspaceListSchema>;

export const workspaceCreateSchema = z.object({
  name: z.string().min(2).describe('Workspace name (min 2 chars)'),
});
export type WorkspaceCreateArgs = z.infer<typeof workspaceCreateSchema>;

export const workspaceSwitchSchema = z.object({
  name: z.string().min(1).describe('Workspace name, ID, or "personal"'),
});
export type WorkspaceSwitchArgs = z.infer<typeof workspaceSwitchSchema>;

export const workspaceMembersSchema = z.object({
  workspace: z.string().optional().describe('Workspace name or ID (defaults to current context)'),
});
export type WorkspaceMembersArgs = z.infer<typeof workspaceMembersSchema>;

interface WorkspaceItem {
  id: string;
  name: string;
  type: string;
  role: string;
  tier?: string;
}

function selectedId(call: CallCtx): string | null {
  return (
    call.ctx.project?.workspaceId ??
    loadSession().defaults.workspace_id ??
    loadGlobalConfig()?.selected_workspace_id ??
    null
  );
}

export async function workspaceList(call: CallCtx, _args: WorkspaceListArgs): Promise<ToolResult> {
  return dispatch(call, 'workspace.list', {}, async () => {
    const sel = selectedId(call);
    if (call.creds.token && call.creds.tokenKind === 'jwt') {
      try {
        const list = (await callControl(call).get('workspaces.list')) as WorkspaceItem[];
        return withContext(call, {
          workspaces: (list ?? []).map((w) => ({ ...w, selected: sel ? w.id === sel : false })),
          source: 'api',
        });
      } catch {
        /* fall through to offline cache */
      }
    }
    const g = loadGlobalConfig();
    if (!g?.workspaces || Object.keys(g.workspaces).length === 0) {
      return fail('No workspaces cached and no API login. Call auth_login, or run `agentsecrets login` with the CLI.');
    }
    return withContext(call, {
      workspaces: Object.entries(g.workspaces)
        .map(([id, ws]) => ({ id, name: ws.name, type: ws.type || 'shared', role: ws.role, selected: sel ? id === sel : false }))
        .sort((a, b) => a.name.localeCompare(b.name)),
      source: 'local cache',
    });
  });
}

export async function workspaceCreate(call: CallCtx, args: WorkspaceCreateArgs): Promise<ToolResult> {
  if (args.name.trim().length < 2) return fail('Workspace name must be at least 2 characters.');
  return dispatch(call, 'workspace.create', { ...args }, async () => {
    const token = needJwt(call.creds);
    const email =
      process.env['AGENTSECRETS_EMAIL']?.trim() || loadGlobalConfig()?.email || null;
    if (!email) {
      throw new Error('workspace_create needs your login email for key wrapping. Set AGENTSECRETS_EMAIL or log in with the CLI once.');
    }
    const pub = (await callControl(call).get('users.public_key', { email })) as { public_key?: string };
    if (!pub.public_key) throw new Error('Server has no public key for this user — complete CLI signup/login first.');
    const wsKey = generateWorkspaceKey();
    const sealed = sealForUser(Buffer.from(pub.public_key, 'base64'), wsKey);
    const created = (await callControl(call).post('workspaces.create', {
      name: args.name.trim(),
      encrypted_workspace_key: sealed.toString('base64'),
    })) as { id: string; name: string; type?: string; role?: string };
    // Cache the minted key in the legacy config slot (same fallback the Go
    // CLI reads) so later set/pull work without re-supplying the key.
    const g = loadGlobalConfig() ?? {};
    const workspaces = { ...(g.workspaces ?? {}) };
    workspaces[created.id] = {
      name: created.name,
      key: wsKey.toString('base64'),
      role: created.role ?? 'owner',
      type: created.type ?? 'shared',
    };
    saveGlobalConfig({ ...g, workspaces, selected_workspace_id: created.id });
    const session = loadSession();
    saveSession({ ...session, defaults: { ...session.defaults, workspace_id: created.id } });
    void token;
    return withContext(call, { status: 'success', workspace: { id: created.id, name: created.name } });
  });
}

export async function workspaceSwitch(call: CallCtx, args: WorkspaceSwitchArgs): Promise<ToolResult> {
  return dispatch(call, 'workspace.switch', { ...args }, async () => {
    const token = needJwt(call.creds);
    void token;
    const list = (await callControl(call).get('workspaces.list')) as WorkspaceItem[];
    const hit = (list ?? []).find(
      (w) => w.id === args.name || w.name === args.name || (args.name === 'personal' && w.type === 'personal')
    );
    if (!hit) throw new Error(`Workspace ${JSON.stringify(args.name)} not found.`);
    const session = loadSession();
    saveSession({ ...session, defaults: { workspace_id: hit.id, project_id: null, project_name: null } });
    return withContext(call, { status: 'success', workspace: { id: hit.id, name: hit.name } });
  });
}

export async function workspaceMembers(call: CallCtx, args: WorkspaceMembersArgs): Promise<ToolResult> {
  return dispatch(call, 'workspace.members', { ...args }, async () => {
    needJwt(call.creds);
    const wsId = args.workspace ?? selectedId(call);
    if (!wsId) throw new Error('No workspace in context. Pass {workspace} or pin defaults via auth_use_identity.');
    let resolved = wsId;
    if (!Object.keys(loadSession().identities).includes(wsId)) {
      // Allow names: match against the API list.
      try {
        const list = (await callControl(call).get('workspaces.list')) as WorkspaceItem[];
        const hit = (list ?? []).find((w) => w.id === wsId || w.name === wsId);
        if (hit) resolved = hit.id;
      } catch {
        /* use as-is; server will 404 clearly */
      }
    }
    const members = await callControl(call).get('workspaces.members', { workspace_id: resolved });
    return withContext(call, { workspace_id: resolved, members });
  });
}

export const workspaceDescriptions = {
  workspace_list:
    'See all workspaces (teams) you belong to, with the active one marked. ' +
    'A workspace groups projects — usually one per team or company. WHEN: you need a workspace name/ID, or the human asks where things live.',
  workspace_create:
    'Create a new team workspace. WHEN: the human explicitly asks for a new team space. ' +
    'Always confirm the exact name in chat first (minimum 2 characters).',
  workspace_switch:
    'Pin which workspace later calls act on, by name, ID, or "personal". ' +
    'WHEN: the human says to switch teams. Confirm in chat first — this changes the scope of everything after it.',
  workspace_members:
    'See who belongs to a workspace (name, email, role, status). Metadata only. ' +
    'WHEN: the human asks who has access, or before sharing work with a team.',
};
