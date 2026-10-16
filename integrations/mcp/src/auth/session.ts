/**
 * Bridge-owned session store: ~/.agentsecrets/mcp-session.json (0600).
 *
 * Holds what the bridge itself mints or is granted — never the user's CLI
 * keychain secrets (unreachable by design):
 *   - OAuth tokens from `auth_login` (access + refresh, with expiry)
 *   - Pinned workload identities: one raw token secret per workspace
 *     (NOT the agt_ id — the secret returned once at issuance), stored TO
 *     the bridge via agent_token_issue during `auth_use_identity`
 *   - Pinned workspace/project defaults for project-less (pure cloud) use
 *
 * Sensitivity is on par with the CLI's historical token.json: 0600 file
 * mode, loose-permission warnings, values never logged or echoed.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { globalDir } from './cliFiles.js';
import { emptySession, type BridgeSession } from '../resolver/types.js';

export function sessionPath(): string {
  return path.join(globalDir(), 'mcp-session.json');
}

function checkPerms(file: string): void {
  if (process.platform === 'win32') return;
  try {
    const mode = fs.statSync(file).mode & 0o777;
    if (mode & 0o077) {
      console.error(
        `[agentsecrets-mcp] warning: session file ${file} is group/world-readable ` +
          `(mode ${mode.toString(8)}); expected 0600. Run: chmod 600 ${file}`
      );
    }
  } catch {
    /* missing is fine */
  }
}

export function loadSession(): BridgeSession {
  const file = sessionPath();
  try {
    const raw = fs.readFileSync(file, 'utf8');
    if (!raw.trim()) return emptySession();
    checkPerms(file);
    const parsed = JSON.parse(raw) as Partial<BridgeSession>;
    const base = emptySession();
    return {
      oauth: parsed.oauth ?? null,
      identities: parsed.identities ?? base.identities,
      defaults: { ...base.defaults, ...(parsed.defaults ?? {}) },
    };
  } catch {
    return emptySession();
  }
}

export function saveSession(session: BridgeSession): void {
  const file = sessionPath();
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file + '.tmp', JSON.stringify(session, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(file + '.tmp', file);
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    /* best effort on Windows */
  }
}

export function clearOAuth(session: BridgeSession): BridgeSession {
  return { ...session, oauth: null };
}

/** Find the pinned identity whose token is currently in use (for scope echo). */
export function findPinForToken(token: string): { workspaceId: string; pin: import('../resolver/types.js').PinnedIdentity } | null {
  const session = loadSession();
  for (const [workspaceId, pin] of Object.entries(session.identities)) {
    if (pin.token === token) return { workspaceId, pin };
  }
  return null;
}

export function isOAuthExpired(oauth: { expires_at: string | null }, skewMs = 5 * 60 * 1000): boolean {
  if (!oauth.expires_at) return false;
  const exp = Date.parse(oauth.expires_at);
  if (Number.isNaN(exp)) return true;
  return exp - Date.now() < skewMs;
}
