/**
 * Control-plane endpoint map. Mirrors pkg/api/client.go `endpointMap`
 * exactly — same keys, same paths, same {placeholders}. Any drift from the
 * Go CLI must be fixed here, not papered over in tools.
 *
 * Envelope: the API wraps payloads in {"data": ...}; the client unwraps it.
 * Auth: Authorization: Bearer <token> (user JWT). Public endpoints need none.
 */

export const DEFAULT_BASE_URL = 'https://api.agentsecrets.tech/api';

export const ENDPOINTS: Record<string, Record<string, string>> = {
  auth: {
    signup: 'auth/register/',
    login: 'auth/login/',
    logout: 'auth/logout/',
    refresh: 'auth/refresh/',
  },
  secrets: {
    list: 'secrets/{project_id}/',
    create: 'secrets/',
    get: 'secrets/{project_id}/{environment}/{key}/',
    update: 'secrets/{project_id}/{environment}/{key}/',
    delete: 'secrets/{project_id}/{environment}/{key}/',
    get_policy: 'secrets/{project_id}/{environment}/{key}/policy/',
    set_policy: 'secrets/{project_id}/{environment}/{key}/policy/',
    rotate_stage: 'secrets/{project_id}/{environment}/{key}/versions/',
    rotate_promote: 'secrets/{project_id}/{environment}/{key}/promote/',
    rotate_rollback: 'secrets/{project_id}/{environment}/{key}/rollback/',
    rotate_abort: 'secrets/{project_id}/{environment}/{key}/versions/pending/',
    rotation_status: 'secrets/{project_id}/{environment}/{key}/rotation/',
    rotation_policy: 'secrets/{project_id}/{environment}/{key}/rotation-policy/',
  },
  projects: {
    list: 'projects/',
    create: 'projects/',
    get: 'projects/{workspace_id}/{project_name}/',
    update: 'projects/{workspace_id}/{project_name}/',
    delete: 'projects/{workspace_id}/{project_name}/',
    invite: 'projects/{workspace_id}/{project_name}/invite/',
  },
  workspaces: {
    list: 'workspaces/',
    create: 'workspaces/',
    get: 'workspaces/{workspace_id}/',
    update: 'workspaces/{workspace_id}/',
    delete: 'workspaces/{workspace_id}/',
    members: 'workspaces/{workspace_id}/members/',
    invite: 'workspaces/{workspace_id}/members/',
    remove_member: 'workspaces/{workspace_id}/members/{user_id}/',
    role_update: 'workspaces/{workspace_id}/members/{user_id}/role/',
    allowlist_list: 'workspaces/{workspace_id}/allowlist/',
    allowlist_add: 'workspaces/{workspace_id}/allowlist/',
    allowlist_remove: 'workspaces/{workspace_id}/allowlist/{domain}/',
    allowlist_log: 'workspaces/{workspace_id}/allowlist/log/',
  },
  agents: {
    list: 'workspaces/{workspace_id}/agents/',
    register: 'workspaces/{workspace_id}/agents/',
    list_project: 'workspaces/{workspace_id}/projects/{project_id}/agents/',
    register_project: 'workspaces/{workspace_id}/projects/{project_id}/agents/',
    delete: 'workspaces/{workspace_id}/agents/{registration_id}/',
    token_issue: 'workspaces/{workspace_id}/agents/{registration_id}/tokens/',
    token_list: 'workspaces/{workspace_id}/agents/{registration_id}/tokens/',
    token_revoke: 'workspaces/{workspace_id}/agents/{registration_id}/tokens/{token_id}/',
    token_rotate: 'workspaces/{workspace_id}/agents/{registration_id}/tokens/{token_id}/rotate/',
    token_rotation_policy:
      'workspaces/{workspace_id}/agents/{registration_id}/tokens/{token_id}/rotation-policy/',
    get_capabilities: 'workspaces/{workspace_id}/agents/{registration_id}/capabilities/',
    set_capabilities: 'workspaces/{workspace_id}/agents/{registration_id}/capabilities/',
    token_revoked: 'workspaces/{workspace_id}/agents/revoked-tokens/',
  },
  log: {
    list: 'audit/logs/',
    detail: 'audit/logs/{log_id}/',
    summary: 'audit/summary/',
    export: 'audit/export/',
  },
  users: {
    public_key: 'users/{email}/public-key/',
  },
};

/**
 * Resolve "category.action" + params into a URL path.
 * Mirrors Client.resolveEndpoint. Unknown keys throw (fail fast).
 */
export function resolveEndpoint(key: string, params?: Record<string, string>): string {
  const dot = key.indexOf('.');
  if (dot < 0) throw new Error(`invalid endpoint key ${JSON.stringify(key)}: must be 'category.action'`);
  const category = key.slice(0, dot);
  const action = key.slice(dot + 1);
  const cat = ENDPOINTS[category];
  const path = cat?.[action];
  if (!path) throw new Error(`unknown endpoint: ${key}`);
  let out = path;
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      out = out.split(`{${k}}`).join(v);
    }
  }
  if (/\{[^}]+\}/.test(out)) {
    throw new Error(`endpoint ${key} has unfilled params: ${out}`);
  }
  return out;
}

/**
 * Validate + normalize a server URL. Mirrors config.NormalizeServerURL:
 * scheme default (http for localhost/127.0.0.1, https otherwise), strip
 * trailing slashes, ensure the /api route prefix when no path is present.
 */
export function normalizeServerUrl(raw: string): string {
  let s = raw.trim();
  if (!s) return DEFAULT_BASE_URL;
  if (!s.startsWith('http://') && !s.startsWith('https://')) {
    if (s.startsWith('localhost') || s.startsWith('127.0.0.1')) s = 'http://' + s;
    else s = 'https://' + s;
  }
  s = s.replace(/\/+$/, '');
  try {
    const u = new URL(s);
    if (u.pathname === '' || u.pathname === '/') s = s + '/api';
  } catch {
    // Leave as-is; fetch will surface a clear network error.
  }
  return s;
}

export function joinUrl(base: string, path: string): string {
  return `${base.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`;
}
