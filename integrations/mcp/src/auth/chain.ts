/**
 * Credential chain — how the bridge authenticates with NO secrets in the
 * MCP client config (Claude Desktop / Cursor JSON) and NO credential
 * required at install time.
 *
 * The keychain-auth daemon verifies caller binary identity at the kernel
 * level and rejects unregistered binaries, so this bridge (an npx script)
 * never attempts keychain access. Credentials resolve from managed,
 * revocable sources first; static files are the LAST resort:
 *
 *   management JWT (control-plane API):
 *     1. AGENTSECRETS_TOKEN env (when JWT-shaped)
 *     2. bridge session store (OAuth login via auth_login, auto-refresh)
 *     3. ~/.agentsecrets/token.json access_token (pre-migration CLI session)
 *     4. AGENTSECRETS_TOKEN_FILE env -> 0600 file (the *path* is config,
 *        the secret is not; see `agentsecrets mcp bridge auth.export`)
 *
 *   workload credential = agent identity (cloud resolver /v1/resolve +
 *   local proxy X-AS-Agent-Token attribution). Either the raw token_urlsafe
 *   secret (verified by hash) or an agt_ identifier (verified by id match) —
 *   the server accepts both, so shape never gates here:
 *     1. AGENTSECRETS_TOKEN env (when NOT JWT-shaped)
 *     2. AS_AGENT_TOKEN | AGENTSECRETS_AGENT_TOKEN env (as given)
 *     3. pinned bridge identity for the active workspace (auth_use_identity)
 *     4. AGENTSECRETS_TOKEN_FILE | AGENTSECRETS_AGENT_TOKEN_FILE
 *
 *   local proxy session: AGENTSECRETS_SESSION_TOKEN -> X-AS-Session-Token
 *   declared identity:   AGENTSECRETS_AGENT_ID -> X-AS-Agent-ID
 *
 *   workspace data key (AES-256-GCM for set/pull/push in cloud mode):
 *     1. AGENTSECRETS_WORKSPACE_KEY env (base64: raw 32B or double-encoded)
 *     2. legacy ~/.agentsecrets/config.json workspaces[id].key
 *     3. AGENTSECRETS_WORKSPACE_KEY_FILE
 *
 * Fail-fast invariant: explicitly configured but invalid credentials
 * surface as auth errors. The bridge NEVER silently falls back to a
 * weaker identity (confused-deputy protection).
 */

import * as fs from 'node:fs';
import { loadLegacyTokens, loadGlobalConfig } from './cliFiles.js';
import { loadSession, saveSession, isOAuthExpired } from './session.js';
import { refreshTokens } from './oauth.js';
import type { Credentials, TokenKind } from '../resolver/types.js';

function readSecretFile(p: string): string | null {
  try {
    const st = fs.statSync(p);
    if (!st.isFile()) return null;
    if (process.platform !== 'win32') {
      const mode = st.mode & 0o777;
      if (mode & 0o077) {
        console.error(
          `[agentsecrets-mcp] warning: secret file ${p} is group/world-readable ` +
            `(mode ${mode.toString(8)}); expected 0600.`
        );
      }
    }
    const v = fs.readFileSync(p, 'utf8').trim();
    return v || null;
  } catch {
    return null;
  }
}

/**
 * JWT-shaped credentials take the login posture; everything else presented
 * as a Bearer credential is a workload credential (raw token_urlsafe secret
 * or agt_ identifier — the server accepts both, by hash or id match).
 * Neither raw secrets nor agt_ ids contain '.', and every JWT does, so the
 * discriminator is simply "contains a dot" — kept in lockstep with the
 * resolver's isWorkloadToken. Garbage fails closed downstream (control
 * plane 401, or resolver hash miss → 401).
 */
export function isJwtShape(token: string): boolean {
  return token.includes('.');
}

/** Decode a workspace key (raw 32B or Fernet-style double-encoded). Exported for tests. */
export function decodeWorkspaceKey(raw: string): Buffer | null {
  const clean = raw.trim().replace(/\s+/g, '');
  if (!clean) return null;
  // Go GetWorkspaceKey tolerance: raw 32 bytes, or the 44-char base64
  // string itself base64-encoded again (Fernet-style double encoding).
  const tryB64 = (s: string): Buffer | null => {
    try {
      const b = Buffer.from(s, 'base64');
      if (b.length === 0) return null;
      return b;
    } catch {
      return null;
    }
  };
  const once = tryB64(clean);
  if (!once) return null;
  if (once.length === 32) return once;
  if (once.length === 44) {
    const inner = tryB64(once.toString('utf8'));
    if (inner && inner.length === 32) return inner;
  }
  return null;
}

export interface ChainOptions {
  /** Workspace for pinned-identity lookup. */
  workspaceId?: string | undefined;
  /** When true, attempt an OAuth refresh for expired session tokens. */
  refresh?: boolean;
}

export async function resolveCredentials(opts: ChainOptions = {}): Promise<Credentials> {
  const creds: Credentials = {
    token: null,
    tokenKind: null,
    tokenSource: null,
    agentToken: null,
    agentId: process.env['AGENTSECRETS_AGENT_ID']?.trim() || null,
    sessionToken: process.env['AGENTSECRETS_SESSION_TOKEN']?.trim() || null,
    workspaceKey: null,
    workspaceKeySource: null,
  };

  // --- management JWT: env, then managed sessions, files last ---
  const envToken = process.env['AGENTSECRETS_TOKEN']?.trim() || null;
  if (envToken && isJwtShape(envToken)) {
    creds.token = envToken;
    creds.tokenKind = 'jwt';
    creds.tokenSource = 'AGENTSECRETS_TOKEN';
  }
  if (!creds.token) {
    const session = loadSession();
    if (session.oauth) {
      let oauth = session.oauth;
      if (opts.refresh !== false) {
        if (isOAuthExpired(oauth) && oauth.refresh_token) {
          try {
            const bundle = await refreshTokens(oauth.token_url, oauth.refresh_token);
            oauth = {
              access_token: bundle.access_token,
              refresh_token: bundle.refresh_token,
              expires_at: bundle.expires_at,
              token_url: oauth.token_url,
              client_id: oauth.client_id,
            };
            saveSession({ ...session, oauth });
          } catch (e) {
            console.error(
              `[agentsecrets-mcp] OAuth refresh failed: ${e instanceof Error ? e.message : String(e)}`
            );
          }
        }
      }
      if (oauth.access_token) {
        creds.token = oauth.access_token;
        creds.tokenKind = 'jwt';
        creds.tokenSource = 'OAuth session (auth_login)';
      }
    }
  }
  if (!creds.token) {
    const legacy = loadLegacyTokens();
    if (legacy?.access_token) {
      creds.token = legacy.access_token;
      creds.tokenKind = 'jwt';
      creds.tokenSource = '~/.agentsecrets/token.json';
    }
  }
  // Static files last: operator-provided headless credentials. The file
  // is still READ here (a workload credential inside feeds workload lookup
  // below); only its use as a management JWT is last-resort.
  let fileToken: string | null = null;
  let fileTokenSource: string | null = null;
  const tokenFile = process.env['AGENTSECRETS_TOKEN_FILE']?.trim() || null;
  if (!envToken && tokenFile) {
    const v = readSecretFile(tokenFile);
    if (v) {
      fileToken = v;
      fileTokenSource = 'AGENTSECRETS_TOKEN_FILE';
    } else {
      console.error(`[agentsecrets-mcp] warning: AGENTSECRETS_TOKEN_FILE=${tokenFile} unreadable or empty.`);
    }
  }
  if (!creds.token && fileToken && isJwtShape(fileToken)) {
    creds.token = fileToken;
    creds.tokenKind = 'jwt';
    creds.tokenSource = fileTokenSource;
  }

  // --- workload token (agent identity): env, pinned, files last ---
  const candidates: Array<{ v: string | null }> = [];
  if (envToken && !isJwtShape(envToken)) candidates.push({ v: envToken });
  const agentEnv =
    process.env['AS_AGENT_TOKEN']?.trim() || process.env['AGENTSECRETS_AGENT_TOKEN']?.trim() || null;
  if (agentEnv) candidates.push({ v: agentEnv });
  let pinnedToken: string | null = null;
  if (opts.workspaceId) {
    const session = loadSession();
    const pinned = session.identities[opts.workspaceId];
    if (pinned?.token) pinnedToken = pinned.token;
  }
  if (pinnedToken) candidates.push({ v: pinnedToken });
  if (fileToken && !isJwtShape(fileToken)) candidates.push({ v: fileToken });
  const agentFile = process.env['AGENTSECRETS_AGENT_TOKEN_FILE']?.trim() || null;
  if (agentFile) {
    const v = readSecretFile(agentFile);
    if (v) candidates.push({ v });
    else {
      console.error(`[agentsecrets-mcp] warning: AGENTSECRETS_AGENT_TOKEN_FILE=${agentFile} unreadable or empty.`);
    }
  }
  const first = candidates[0];
  if (first?.v) {
    creds.agentToken = first.v;
  }

  // --- workspace data key: env, legacy cache, files last ---
  const wsEnv = process.env['AGENTSECRETS_WORKSPACE_KEY']?.trim() || null;
  if (wsEnv) {
    const k = decodeWorkspaceKey(wsEnv);
    if (k) {
      creds.workspaceKey = k;
      creds.workspaceKeySource = 'AGENTSECRETS_WORKSPACE_KEY';
    } else {
      console.error('[agentsecrets-mcp] warning: AGENTSECRETS_WORKSPACE_KEY is not a valid 32-byte key; ignoring.');
    }
  }
  if (!creds.workspaceKey && opts.workspaceId) {
    const g = loadGlobalConfig();
    const cached = g?.workspaces?.[opts.workspaceId]?.key;
    if (cached) {
      const k = decodeWorkspaceKey(cached);
      if (k) {
        creds.workspaceKey = k;
        creds.workspaceKeySource = 'global config cache';
      }
    }
  }
  if (!creds.workspaceKey) {
    const kf = process.env['AGENTSECRETS_WORKSPACE_KEY_FILE']?.trim() || null;
    if (kf) {
      const v = readSecretFile(kf);
      const k = v ? decodeWorkspaceKey(v) : null;
      if (k) {
        creds.workspaceKey = k;
        creds.workspaceKeySource = 'AGENTSECRETS_WORKSPACE_KEY_FILE';
      } else {
        console.error(`[agentsecrets-mcp] warning: AGENTSECRETS_WORKSPACE_KEY_FILE=${kf} unreadable or not a 32-byte key.`);
      }
    }
  }

  return creds;
}

export type { TokenKind };
