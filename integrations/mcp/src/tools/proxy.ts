/**
 * Proxy / credentialed-call tools. The zero-knowledge core: secret VALUES
 * never cross the MCP tool boundary in either direction, in any mode.
 *
 * - local: `proxy.call` via the CLI helper (CallViaProxy: running proxy or
 *   transient engine, session token from keychain, full injection styles,
 *   allowlist + policy + audit enforced by the engine).
 * - cloud, proxy reachable on this machine: direct HTTP to the local proxy
 *   with the X-AS-* header protocol (session token from
 *   AGENTSECRETS_SESSION_TOKEN). Same ZK guarantee, no cloud billing.
 * - cloud, otherwise: POST {resolver}/v1/resolve with the workload token.
 *   Injection specs translate to {{KEY}} handles substituted server-side
 *   (capability + policy + allowlist enforced, response redacted).
 *   `basic` and `query` styles are rejected here: the resolver only
 *   substitutes handles in header values and the body, so basic-auth
 *   base64 and query-param placement cannot be expressed — use local
 *   mode for those.
 */

import { z } from 'zod';
import type { CallCtx } from '../resolver/index.js';
import { fail, ok, type ProxyHealth, type ToolResult } from '../resolver/types.js';
import { dispatch, sanitize, withContext } from './common.js';
import { needJwt } from '../resolver/guards.js';
import { cloudResolve, cloudHealth, ApiError, type ResolveRequest } from '../resolver/client.js';
import { resolverBaseUrl } from '../resolver/index.js';
import { readProxyPid } from '../auth/cliFiles.js';
import { findPinForToken } from '../auth/session.js';

export const proxyCallSchema = z.object({
  url: z.string().url().describe('Target HTTPS API URL (e.g. https://api.stripe.com/v1/charges)'),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).default('GET'),
  injections: z
    .record(z.string(), z.string())
    .describe(
      'Map of injection_spec to secret KEY NAME (never values). ' +
        'Specs: "bearer", "basic", "header:X-Name", "query:param", "body:json.path", "form:field". ' +
        'Example: {"bearer": "STRIPE_KEY"} or {"header:X-Api-Key": "API_KEY"}. ' +
        'Cloud mode supports bearer/header/body/form; basic and query need local mode.'
    ),
  headers: z.record(z.string(), z.string()).optional().describe('Extra request headers (non-credential)'),
  body: z.string().optional().describe('Request body as a string (JSON for body:/form: injections)'),
  agent_id: z.string().optional().describe('Declared agent identity for audit attribution'),
  environment: z.string().optional().describe('Asserts the expected environment (cloud: must match the pinned identity scope; does not re-scope the token)'),
  project: z.string().optional().describe('Project name/ID for context (resolves workspace identity)'),
  workspace: z.string().optional().describe('Workspace name/ID for context'),
  path: z.string().optional().describe('Project directory (local mode cwd)'),
});
export type ProxyCallArgs = z.infer<typeof proxyCallSchema>;

export const proxyStatusSchema = z.object({});
export type ProxyStatusArgs = z.infer<typeof proxyStatusSchema>;

const SESSION_TOKEN_INVALID = 'Invalid or missing session token';

async function probeLocalProxy(timeoutMs = 200): Promise<{ port: number; health: ProxyHealth } | null> {
  const ports: number[] = [];
  const pidPort = portFromPidFile();
  const envPort = [process.env['AGENTSECRETS_PROXY_PORT'], process.env['AGENTSECRETS_PORT']]
    .map((v) => (v ? Number.parseInt(v, 10) : NaN))
    .find((n) => Number.isFinite(n) && n > 0 && n < 65536);
  if (pidPort) ports.push(pidPort);
  if (envPort && !ports.includes(envPort)) ports.push(envPort);
  if (!ports.includes(8765)) ports.push(8765);
  for (const port of ports) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        const res = await fetch(`http://127.0.0.1:${port}/health`, { signal: ctrl.signal });
        if (res.ok) {
          const health = (await res.json()) as ProxyHealth;
          return { port, health };
        }
      } finally {
        clearTimeout(t);
      }
    } catch {
      /* try next */
    }
  }
  return null;
}

function portFromPidFile(): number | null {
  return readProxyPid()?.port ?? null;
}

interface LocalProxyResult {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

/** Direct HTTP call to a running local proxy (X-AS-* protocol). */
async function callLocalProxy(
  port: number,
  args: ProxyCallArgs,
  call: CallCtx
): Promise<LocalProxyResult> {
  const headers: Record<string, string> = {};
  if (call.creds.sessionToken) headers['X-AS-Session-Token'] = call.creds.sessionToken;
  headers['X-AS-Target-URL'] = args.url;
  headers['X-AS-Method'] = args.method;
  const agentId = args.agent_id ?? call.creds.agentId ?? 'mcp-bridge';
  if (agentId) headers['X-AS-Agent-ID'] = agentId;
  if (call.creds.agentToken) headers['X-AS-Agent-Token'] = call.creds.agentToken;
  for (const [spec, key] of Object.entries(args.injections)) {
    const [style, ...rest] = spec.split(':');
    const target = rest.join(':');
    switch ((style ?? '').toLowerCase()) {
      case 'bearer':
        headers['X-AS-Inject-Bearer'] = key;
        break;
      case 'basic':
        headers['X-AS-Inject-Basic'] = key;
        break;
      case 'header':
        if (!target) throw new Error(`header injection requires a target — use "header:Name" format`);
        headers[`X-AS-Inject-Header-${target}`] = key;
        break;
      case 'query':
        if (!target) throw new Error(`query injection requires a target — use "query:param" format`);
        headers[`X-AS-Inject-Query-${target}`] = key;
        break;
      case 'body':
        if (!target) throw new Error(`body injection requires a target — use "body:path" format`);
        headers[`X-AS-Inject-Body-${target.replace(/\./g, '-')}`] = key;
        break;
      case 'form':
        if (!target) throw new Error(`form injection requires a target — use "form:field" format`);
        headers[`X-AS-Inject-Form-${target}`] = key;
        break;
      default:
        throw new Error(`unknown injection style ${JSON.stringify(spec)} — valid: bearer, basic, header:name, query:param, body:path, form:field`);
    }
  }
  for (const [k, v] of Object.entries(args.headers ?? {})) {
    if (!k.toLowerCase().startsWith('x-as-')) headers[k] = v;
  }
  const res = await fetch(`http://127.0.0.1:${port}/proxy`, {
    method: 'POST',
    headers,
    ...(args.body !== undefined ? { body: args.body } : {}),
    signal: AbortSignal.timeout(60000),
  });
  const text = await res.text();
  if (res.status === 401) {
    let msg = text;
    try {
      const j = JSON.parse(text) as { error?: string };
      if (j.error) msg = j.error;
    } catch {
      /* keep text */
    }
    if (msg.includes(SESSION_TOKEN_INVALID)) {
      throw new Error(
        'Local proxy requires its session token (401). Set AGENTSECRETS_SESSION_TOKEN, ' +
          'or install the CLI so local mode handles the session automatically.'
      );
    }
  }
  const outHeaders: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    outHeaders[k] = v;
  });
  return { statusCode: res.status, headers: outHeaders, body: text };
}

/** Translate local injection specs to cloud-resolver {{KEY}} handles. Exported for tests. */
export function toResolveRequest(args: ProxyCallArgs): ResolveRequest {
  const u = new URL(args.url);
  if (u.protocol !== 'https:') {
    throw new Error('Cloud credentialed calls require an https:// target URL.');
  }
  const headers: Record<string, string> = { ...(args.headers ?? {}) };
  let body = args.body ?? '';
  for (const [spec, key] of Object.entries(args.injections)) {
    const [style, ...rest] = spec.split(':');
    const target = rest.join(':');
    const handle = `{{${key}}}`;
    switch ((style ?? '').toLowerCase()) {
      case 'bearer':
        headers['Authorization'] = `Bearer ${handle}`;
        break;
      case 'header':
        if (!target) throw new Error(`header injection requires a target — use "header:Name" format`);
        headers[target] = handle;
        break;
      case 'body': {
        if (!target) throw new Error(`body injection requires a target — use "body:path" format`);
        let obj: Record<string, unknown> = {};
        if (body) {
          try {
            const parsed: unknown = JSON.parse(body);
            if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) obj = parsed as Record<string, unknown>;
            else throw new Error('body injection needs a JSON object body in cloud mode');
          } catch {
            throw new Error('body injection needs a JSON object body in cloud mode');
          }
        }
        setPath(obj, target, handle);
        body = JSON.stringify(obj);
        headers['Content-Type'] = 'application/json';
        break;
      }
      case 'form': {
        if (!target) throw new Error(`form injection requires a target — use "form:field" format`);
        if (body && !body.includes('=')) {
          throw new Error('form injection cannot merge into a non-urlencoded body — use local mode or a urlencoded/empty body');
        }
        const params = new URLSearchParams(body || '');
        params.set(target, handle);
        body = params.toString();
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
        break;
      }
      case 'basic':
        throw new Error(
          'basic-auth injection is not expressible in cloud mode (the resolver substitutes handles, it cannot base64-encode). Use local mode (CLI installed) for basic auth.'
        );
      case 'query':
        throw new Error(
          'query-param injection is not expressible in cloud mode (handles substitute in headers/body only). Use local mode (CLI installed) for query auth.'
        );
      default:
        throw new Error(`unknown injection style ${JSON.stringify(spec)} — valid: bearer, basic, header:name, query:param, body:path, form:field`);
    }
  }
  return { target_url: args.url, method: args.method, headers, body };
}

function setPath(obj: Record<string, unknown>, dotted: string, value: string): void {
  const parts = dotted.split('.').filter(Boolean);
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const p = parts[i] as string;
    const next = cur[p];
    if (!next || typeof next !== 'object' || Array.isArray(next)) cur[p] = {};
    cur = cur[p] as Record<string, unknown>;
  }
  cur[parts[parts.length - 1] as string] = value;
}

export async function proxyCall(call: CallCtx, args: ProxyCallArgs): Promise<ToolResult> {
  // The SDK may pass raw input without applying zod defaults.
  const effective: ProxyCallArgs = { ...args, method: args.method ?? 'GET' };
  const argv = { ...effective };
  if (Object.keys(argv.injections).length === 0) {
    return fail('missing required parameter: injections — provide at least one like {"bearer": "SECRET_KEY"}');
  }
  return dispatch(call, 'proxy.call', { ...argv }, async () => {
    // Cloud mode prefers a reachable local proxy (same ZK, no billing, offline).
    const probed = await probeLocalProxy();
    if (probed) {
      try {
        const r = await callLocalProxy(probed.port, argv, call);
        return withContext(call, {
          status_code: r.statusCode,
          headers: r.headers,
          body: r.body,
          via: 'local-proxy',
          scope: {
            source: 'local-proxy',
            workspace_id: call.ctx.project?.workspaceId ?? null,
            project_id: call.ctx.project?.projectId ?? null,
            environment: call.ctx.env.name,
            matches_request: true,
          },
        });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        if (!msg.includes('session token')) throw e;
        return fail(msg);
      }
    }
    const req = toResolveRequest(args);
    // Posture selection, least-privilege first: a workload credential
    // (agent identity: raw token secret or agt_ identifier) wins when
    // present; otherwise the user login is presented with an explicit
    // scope (login posture).
    if (call.creds.agentToken) {
      const scope = enforceTokenScope(call, argv, call.creds.agentToken);
      try {
        const r = await cloudResolve(resolverBaseUrl(), call.creds.agentToken, req);
        return withContext(call, {
          status_code: r.status_code,
          headers: r.headers,
          body: r.body,
          redacted: r.redacted,
          via: 'cloud-resolver',
          auth_posture: 'workload-token',
          scope,
        });
      } catch (e) {
        if (e instanceof ApiError && e.status === 402) {
          return fail(`${sanitize(e.message)} — cloud resolution is a billed entitlement.`);
        }
        throw e;
      }
    }
    const jwt = needJwt(call.creds);
    const scope = buildRequestedScope(call, argv);
    try {
      const r = await cloudResolve(resolverBaseUrl(), jwt, { ...req, scope: scope.fields });
      return withContext(call, {
        status_code: r.status_code,
        headers: r.headers,
        body: r.body,
        redacted: r.redacted,
        via: 'cloud-resolver',
        auth_posture: 'user-login',
        scope: { source: 'user-login (server-authorized)', ...scope.fields, matches_request: true },
      });
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        throw new Error(
          'Cloud resolver rejected the user login for credentialed calls: this resolver predates ' +
            'login-posture support. Options: pin a workload identity via auth_use_identity (works everywhere), ' +
            'or upgrade the resolver to a version accepting user logins with explicit scope.'
        );
      }
      throw e;
    }
  });
}

interface ScopeEcho {
  source: string;
  workspace_id: string | null;
  project_id: string | null;
  environment: string | null;
  matches_request: boolean | null;
  note?: string;
}

/**
 * Token posture: the token triple is authoritative. Fail closed BEFORE
 * spending quota when the requested context disagrees with the pinned
 * scope. Ad-hoc (env-supplied) tokens have unknown scope: proceed with
 * the server as the only enforcer, and say so.
 */
function enforceTokenScope(call: CallCtx, args: ProxyCallArgs, token: string): ScopeEcho {
  const found = findPinForToken(token);
  const reqWs = call.ctx.project?.workspaceId ?? null;
  const reqProj = call.ctx.project?.projectId ?? null;
  const reqEnv = args.environment ?? call.ctx.env.name;
  if (!found) {
    return {
      source: 'adhoc-token',
      workspace_id: null,
      project_id: null,
      environment: null,
      matches_request: null,
      note: 'Token scope is token-defined but unknown to the bridge (supplied via env, not pinned). The server enforces scope; call auth_use_identity to pin an identity and enable pre-call scope checks.',
    };
  }
  const pin = found.pin;
  if (reqWs && reqWs !== pin.workspace_id) {
    throw new Error(
      `Scope mismatch: call targets workspace ${reqWs} but the pinned identity ${pin.agent_name} belongs to ${pin.workspace_id}. ` +
        `Call auth_use_identity with {workspace} to pin that workspace (no extra identities needed beyond one per workspace).`
    );
  }
  if (reqProj && pin.project_id && reqProj !== pin.project_id) {
    throw new Error(
      `Scope mismatch: call targets project ${reqProj} but the pinned identity is scoped to project ${pin.project_id}. ` +
        `Pin a project-scoped identity for the target project via auth_use_identity.`
    );
  }
  if (pin.environment && reqEnv !== pin.environment) {
    throw new Error(
      `Scope mismatch: call environment ${reqEnv} but the pinned identity is scoped to ${pin.environment}. ` +
        `Pass {environment: ${pin.environment}} or re-pin via auth_use_identity with {environment}.`
    );
  }
  return {
    source: 'pinned-identity',
    workspace_id: pin.workspace_id,
    project_id: pin.project_id,
    environment: pin.environment,
    matches_request: true,
  };
}

/** Login posture: assemble the explicit scope the server must authorize. */
function buildRequestedScope(call: CallCtx, args: ProxyCallArgs): { fields: { workspace_id?: string; project_id?: string; environment?: string } } {
  const ws = call.ctx.project?.workspaceId ?? null;
  if (!ws) {
    throw new Error(
      'Login-posture cloud calls need a target scope: pass {project, workspace}, run from a project directory, or pin defaults via auth_use_identity.'
    );
  }
  const fields: { workspace_id?: string; project_id?: string; environment?: string } = { workspace_id: ws };
  if (call.ctx.project?.projectId) fields['project_id'] = call.ctx.project.projectId;
  fields['environment'] = args.environment ?? call.ctx.env.name;
  return { fields };
}

export async function proxyStatus(call: CallCtx): Promise<ToolResult> {
  return dispatch(call, 'proxy.status', {}, async () => {
    const probed = await probeLocalProxy();
    const cloud = await cloudHealth(resolverBaseUrl());
    return withContext(call, {
      local_proxy: probed
        ? { reachable: true, port: probed.port, health: probed.health }
        : { reachable: false, hint: 'Run `agentsecrets proxy start` for local zero-knowledge calls.' },
      cloud_resolver: cloud ? { reachable: true } : { reachable: false },
    });
  });
}

export const proxyCallDescription =
  'Call any HTTPS API using a stored secret, WITHOUT ever seeing the secret value. ' +
  'WHEN: the human asks you to use an external API (check a balance, send a message, fetch data). ' +
  'You pass the secret KEY NAME (e.g. STRIPE_KEY — never the value) plus the target URL; the value is ' +
  'injected outside your reach and only the API response returns. ' +
  'If you do not know the key name, call secrets_list first. ' +
  'Injections map how the secret travels: {"bearer": "KEY"} for Authorization: Bearer, ' +
  '{"header:X-Api-Key": "KEY"} for a custom header, {"query:key": "KEY"} for a URL parameter, ' +
  '{"body:client_secret": "KEY"} for a JSON body field, {"form:api_key": "KEY"} for a form field. ' +
  'One injection is enough for most APIs. Target URLs must be https.';
export const proxyStatusDescription =
  'Check whether credentialed calls can be served right now: local proxy reachability and cloud resolver reachability. ' +
  'WHEN: proxy_call fails with a connectivity or session error — call this before retrying, and follow its hint. Takes no inputs.';
