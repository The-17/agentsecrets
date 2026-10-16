/**
 * Mode guards. Every tool is registered unconditionally so the model
 * always sees the full surface; handlers fail here with actionable
 * guidance instead of cryptic transport errors. Handlers return
 * {isError:true} (never throw for expected unavailability) — mirroring
 * the Go MCP server's NewToolResultError behavior.
 */

import type { Credentials } from './types.js';

export function setupGuidance(): string {
  return (
    'Not authenticated. Options (no secrets in MCP config): ' +
    '1) call auth_login for browser OAuth (zero-config); ' +
    '2) run `agentsecrets login` then `agentsecrets mcp bridge auth.export > ~/.agentsecrets/mcp-token` (0600) and set AGENTSECRETS_TOKEN_FILE to that path; ' +
    '3) install the CLI so local mode activates automatically. ' +
    'Call auth_status to inspect the current state.'
  );
}

/** Management JWT (control-plane API). Workload credentials are rejected here. */
export function needJwt(creds: Credentials): string {
  if (creds.token && creds.tokenKind === 'jwt') return creds.token;
  if (creds.tokenKind === 'workload') {
    throw new Error(
      'This tool needs a user login (JWT), but only a workload credential is configured. ' +
        'Workload credentials are resolve-only identities. ' +
        (process.env['AGENTSECRETS_TOKEN'] ? 'AGENTSECRETS_TOKEN holds a workload token — ' : '') +
        'Call auth_login for OAuth, or set AGENTSECRETS_TOKEN_FILE to exported user tokens.'
    );
  }
  throw new Error(setupGuidance());
}

/** Workload token = agent identity (cloud resolver + proxy attribution). */
export function needResolveToken(creds: Credentials, workspaceHint?: string | null): string {
  if (creds.agentToken) return creds.agentToken;
  throw new Error(
    'No workload token (agent identity) available' +
      (workspaceHint ? ` for workspace ${workspaceHint}` : '') +
      '. Options: call auth_use_identity to pin the bridge identity for this workspace ' +
      '(issues a scoped token automatically), or set AS_AGENT_TOKEN / AGENTSECRETS_AGENT_TOKEN(_FILE).'
  );
}

export function needWorkspaceKey(creds: Credentials, op: string): Buffer {
  if (creds.workspaceKey) return creds.workspaceKey;
  throw new Error(
    `${op} needs the workspace data key for client-side AES-256-GCM, which is unavailable. ` +
      'Options: install the CLI (local mode holds keys in the OS keychain), or set ' +
      'AGENTSECRETS_WORKSPACE_KEY(_FILE) to the base64 32-byte key for headless operation.'
  );
}
