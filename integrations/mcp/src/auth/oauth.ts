/**
 * OAuth 2.1 Authorization Code + PKCE client (RFC 7636 / RFC 8252 loopback).
 *
 * Used by the `auth_login` tool so the bridge can authenticate with NO
 * credential pre-configured: the human opens the returned URL in a
 * browser, approves, and the loopback callback completes the exchange in
 * the background. Tokens land in the 0600 session store — never in MCP
 * client config, never in chat.
 *
 * Server contract (control plane — required endpoints):
 *   GET  {control}/.well-known/oauth-authorization-server   (optional discovery)
 *   GET  {control}/oauth/authorize?response_type=code&client_id=agentsecrets-mcp
 *        &redirect_uri=http://127.0.0.1:{port}/callback&scope=...&state=...&code_challenge=...
 *   POST {control}/oauth/token  {grant_type: authorization_code|refresh_token, ...}
 *
 * If the control plane does not serve these yet, every method throws
 * OAuthNotAvailable with fallback instructions (CLI token-export flow).
 * The bridge never fakes a login.
 */

import * as crypto from 'node:crypto';
import * as http from 'node:http';

export class OAuthNotAvailable extends Error {
  constructor(server: string) {
    super(
      `OAuth is not available on ${server} yet (no oauth endpoints). ` +
        `Use the terminal flow instead: run \`agentsecrets login\`, then ` +
        `\`agentsecrets mcp bridge auth.export > ~/.agentsecrets/mcp-token\` ` +
        `with mode 0600, and set AGENTSECRETS_TOKEN_FILE to that path. ` +
        `Then call auth_status to verify.`
    );
    this.name = 'OAuthNotAvailable';
  }
}

export interface OAuthEndpoints {
  authorization: string;
  token: string;
}

export interface TokenBundle {
  access_token: string;
  refresh_token: string | null;
  expires_at: string | null;
}

const CLIENT_ID = 'agentsecrets-mcp';
const LOOPBACK_HOST = '127.0.0.1';

function trimApiSuffix(base: string): string {
  return base.replace(/\/+$/, '').replace(/\/api$/, '');
}

async function fetchJson(url: string, init?: RequestInit, timeoutMs = 8000): Promise<{ status: number; json: unknown }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    let json: unknown = null;
    try {
      json = await res.json();
    } catch {
      json = null;
    }
    return { status: res.status, json };
  } finally {
    clearTimeout(t);
  }
}

/** Discover OAuth endpoints, falling back to the conventional paths. */
export async function discoverEndpoints(controlBase: string): Promise<OAuthEndpoints> {
  const root = trimApiSuffix(controlBase);
  try {
    const { status, json } = await fetchJson(`${root}/.well-known/oauth-authorization-server`);
    if (status === 200 && json && typeof json === 'object') {
      const m = json as Record<string, unknown>;
      if (typeof m['authorization_endpoint'] === 'string' && typeof m['token_endpoint'] === 'string') {
        return { authorization: m['authorization_endpoint'], token: m['token_endpoint'] };
      }
    }
  } catch {
    /* fall through to conventional paths */
  }
  // Probe the conventional authorize path before committing to it.
  // A 404/405 here (vs 200/302/400) means OAuth is not served yet.
  try {
    const { status } = await fetchJson(`${root}/oauth/authorize?client_id=${CLIENT_ID}`, undefined, 5000);
    if (status === 404) throw new OAuthNotAvailable(controlBase);
  } catch (e) {
    if (e instanceof OAuthNotAvailable) throw e;
    // Network failure is distinct from "not served": surface as-is.
    throw new Error(`OAuth discovery failed for ${controlBase}: ${e instanceof Error ? e.message : String(e)}`);
  }
  return { authorization: `${root}/oauth/authorize`, token: `${root}/oauth/token` };
}

export interface PendingLogin {
  authUrl: string;
  /** Resolves with the token bundle once the human completes browser approval. */
  done: Promise<TokenBundle>;
  cancel: () => void;
}

function base64url(b: Buffer): string {
  return b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Start a PKCE loopback login. Returns immediately with the URL for the
 * human; `done` settles when the callback arrives (or rejects on timeout /
 * error / explicit denial). The caller (auth_login tool) returns the URL
 * and instructions; auth_status reflects completion on the next call.
 */
export async function startLogin(
  endpoints: OAuthEndpoints,
  scopes: string[] = ['read', 'write'],
  timeoutMs = 10 * 60 * 1000
): Promise<PendingLogin> {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
  const state = base64url(crypto.randomBytes(16));

  let resolveDone!: (b: TokenBundle) => void;
  let rejectDone!: (e: Error) => void;
  const done = new Promise<TokenBundle>((res, rej) => {
    resolveDone = res;
    rejectDone = rej;
  });
  // Avoid unhandled rejection when the tool returns before completion.
  done.catch(() => undefined);

  const server = http.createServer();
  const cleanup = (): void => {
    clearTimeout(timer);
    server.close();
  };
  const timer = setTimeout(() => {
    cleanup();
    rejectDone(new Error('Login timed out after 10 minutes. Call auth_login again for a fresh URL.'));
  }, timeoutMs);
  timer.unref?.();

  server.on('request', (req, res) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? '/', `http://${LOOPBACK_HOST}`);
        if (url.pathname !== '/callback') {
          res.writeHead(404, { 'Content-Type': 'text/plain' }).end('not found');
          return;
        }
        const err = url.searchParams.get('error');
        const code = url.searchParams.get('code');
        const returnedState = url.searchParams.get('state');
        if (err || !code) {
          res.writeHead(200, { 'Content-Type': 'text/html' }).end(
            '<h1>Login cancelled</h1><p>You can close this tab and return to your agent.</p>'
          );
          cleanup();
          rejectDone(new Error(`Login was not approved (${err ?? 'no code returned'}).`));
          return;
        }
        if (returnedState !== state) {
          res.writeHead(400, { 'Content-Type': 'text/plain' }).end('state mismatch');
          cleanup();
          rejectDone(new Error('Login failed: state mismatch (possible CSRF). Try again.'));
          return;
        }
        const bundle = await exchangeCode(endpoints, code, redirectUri(), verifier);
        res.writeHead(200, { 'Content-Type': 'text/html' }).end(
          '<h1>AgentSecrets connected</h1><p>You can close this tab and return to your agent. Run auth_status there to verify.</p>'
        );
        cleanup();
        resolveDone(bundle);
      } catch (e) {
        try {
          res.writeHead(500, { 'Content-Type': 'text/plain' }).end('login failed');
        } catch {
          /* already responding */
        }
        cleanup();
        rejectDone(e instanceof Error ? e : new Error(String(e)));
      }
    })();
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, LOOPBACK_HOST, () => resolve());
  });
  const port = (server.address() as { port: number }).port;

  function redirectUri(): string {
    return `http://${LOOPBACK_HOST}:${port}/callback`;
  }

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: redirectUri(),
    scope: scopes.join(' '),
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  return {
    authUrl: `${endpoints.authorization}?${params.toString()}`,
    done,
    cancel: () => {
      cleanup();
      rejectDone(new Error('Login cancelled.'));
    },
  };
}

async function exchangeCode(
  endpoints: OAuthEndpoints,
  code: string,
  redirectUri: string,
  verifier: string
): Promise<TokenBundle> {
  const { status, json } = await fetchJson(
    endpoints.token,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: CLIENT_ID,
        code_verifier: verifier,
      }),
    },
    15000
  );
  if (status === 404) throw new OAuthNotAvailable(endpoints.token);
  if (status < 200 || status >= 300 || !json || typeof json !== 'object') {
    throw new Error(`Token exchange failed (status ${status}).`);
  }
  return toBundle(json as Record<string, unknown>, endpoints.token);
}

export async function refreshTokens(
  tokenUrl: string,
  refreshToken: string
): Promise<TokenBundle> {
  const { status, json } = await fetchJson(
    tokenUrl,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: CLIENT_ID }),
    },
    15000
  );
  if (status === 404) throw new OAuthNotAvailable(tokenUrl);
  if (status < 200 || status >= 300 || !json || typeof json !== 'object') {
    throw new Error('Refresh failed — the session may be revoked. Call auth_login again.');
  }
  const bundle = toBundle(json as Record<string, unknown>, tokenUrl);
  // Some servers omit a rotated refresh token: keep the old one.
  if (!bundle.refresh_token) bundle.refresh_token = refreshToken;
  return bundle;
}

function toBundle(m: Record<string, unknown>, tokenUrl: string): TokenBundle {
  const access = m['access_token'];
  if (typeof access !== 'string' || !access) throw new Error('Token response had no access_token.');
  const refresh = typeof m['refresh_token'] === 'string' ? m['refresh_token'] : null;
  let expiresAt: string | null = null;
  if (typeof m['expires_at'] === 'string') expiresAt = m['expires_at'];
  else if (typeof m['expires_in'] === 'number') expiresAt = new Date(Date.now() + m['expires_in'] * 1000).toISOString();
  return { access_token: access, refresh_token: refresh, expires_at: expiresAt };
}

export { CLIENT_ID };
