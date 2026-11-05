/**
 * HTTPS clients for the two cloud surfaces:
 *   - control plane (Django API, Go endpoint map): management + metadata.
 *     Auth: Authorization: Bearer <user JWT>. Envelope {"data": ...}.
 *   - cloud resolver (agentsecrets-cloud): POST /v1/resolve for
 *     credentialed calls. Auth: Authorization: Bearer <workload credential>
 *     (raw token secret or agt_ identifier — server accepts both).
 *     Secrets are referenced as {{KEY}} handles and substituted
 *     server-side; only the sanitized upstream response returns.
 */

import { resolveEndpoint, joinUrl } from './endpoints.js';

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

function timeoutSignal(ms: number): AbortSignal {
  const s = AbortSignal as unknown as { timeout?: (ms: number) => AbortSignal };
  if (typeof s.timeout === 'function') return s.timeout(ms);
  const c = new AbortController();
  setTimeout(() => c.abort(), ms).unref?.();
  return c.signal;
}

function decodeError(status: number, bodyText: string): string {

  let msg = bodyText.slice(0, 500);
  try {
    const j = JSON.parse(bodyText) as Record<string, unknown>;
    const cand = [j['message'], j['error'], j['detail']];
    for (const c of cand) {
      if (typeof c === 'string' && c) {
        msg = c;
        break;
      }
    }
    // Cloud resolver error shape: {error_code, message}.
    if (typeof j['error_code'] === 'string' && typeof j['message'] === 'string') {
      msg = `${j['error_code']}: ${j['message']}`;
    }
  } catch {
    /* keep snippet */
  }
  if (!msg) msg = `status ${status}`;
  if (status === 401) {
    msg += ' — session may be expired. Call auth_login (OAuth) or refresh AGENTSECRETS_TOKEN(_FILE).';
  }
  return msg;
}

/**
 * A 3xx is not an answer. Both surfaces have a fixed origin, so a redirect is
 * always a protocol error: following it would resend the caller's
 * Authorization header to a host that never proved it owns the credential
 * (client-side SSRF). Refuse before reading the body.
 */
function rejectRedirect(status: number): void {
  if (status >= 300 && status < 400) {
    throw new ApiError(status, `server answered with a redirect (${status}) and was not followed`);
  }
}

/**
 * Cap how much of a 2xx body the client will buffer. A hostile or buggy peer
 * must not be able to exhaust memory with a huge body. Reads the stream and
 * throws once it would exceed maxBytes (one byte of slack detects the overrun).
 */
export const MAX_RESPONSE_BYTES = 12 * 1024 * 1024; // 12 MiB

async function readCapped(res: Response, maxBytes: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) {
    // No stream (e.g. some test shims): fall back to a bounded text read.
    const text = await res.text();
    if (text.length > maxBytes) {
      throw new ApiError(res.status, `response body exceeds ${maxBytes} bytes; refusing to buffer it`);
    }
    return text;
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new ApiError(res.status, `response body exceeds ${maxBytes} bytes; refusing to buffer it`);
      }
      chunks.push(value);
    }
  }
  return new TextDecoder().decode(concat(chunks));
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

export interface ControlOptions {
  body?: unknown;
  urlParams?: Record<string, string> | undefined;
  query?: Record<string, string> | undefined;
  timeoutMs?: number;
}

export interface ControlResult {
  status: number;
  data: unknown;
}

/** Call the control-plane API and unwrap the {data} envelope. */
export async function controlCall(
  baseUrl: string,
  token: string,
  endpointKey: string,
  method: string,
  opts: ControlOptions = {}
): Promise<ControlResult> {
  const path = resolveEndpoint(endpointKey, opts.urlParams);
  let url = joinUrl(baseUrl, path);
  if (opts.query) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(opts.query)) if (v) q.set(k, v);
    const s = q.toString();
    if (s) url += `?${s}`;
  }
  let res: Response;
  try {
    const init: RequestInit = {
      method,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Authorization: `Bearer ${token}`,
      },
      signal: timeoutSignal(opts.timeoutMs ?? 30000),
      redirect: 'manual',
    };
    if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
    res = await fetch(url, init);
  } catch (e) {
    throw new ApiError(0, `network error contacting ${baseUrl}: ${e instanceof Error ? e.message : String(e)}`);
  }
  rejectRedirect(res.status);
  const text = await readCapped(res, MAX_RESPONSE_BYTES);
  if (res.status < 200 || res.status >= 300) {
    throw new ApiError(res.status, decodeError(res.status, text));
  }
  if (!text.trim()) return { status: res.status, data: null };
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new ApiError(res.status, 'server returned non-JSON success body');
  }
  if (json && typeof json === 'object' && 'data' in json) {
    return { status: res.status, data: (json as Record<string, unknown>)['data'] };
  }
  return { status: res.status, data: json };
}

export interface ResolveRequest {
  target_url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
  /**
   * Explicit authorization/narrowing scope. For the login posture the resolver
   * MUST authorize every field against the JWT identity server-side and reject
   * out-of-scope values with 403; absent fields fall back to legacy behavior.
   * For a workload token the token's own triple stays authoritative — project_id
   * is consulted only when the token has no project binding (a workspace-wide
   * identity), where it narrows the lookup to the named project. Workspace and
   * environment never widen a binding.
   */
  scope?: {
    workspace_id?: string;
    project_id?: string;
    environment?: string;
  };
}

export interface ResolveResponse {
  status_code: number;
  headers: Record<string, string>;
  body: string;
  redacted: boolean;
}

/** Credentialed call via the cloud resolver (handle substitution server-side). */
export async function cloudResolve(
  resolverBase: string,
  workloadToken: string,
  req: ResolveRequest,
  timeoutMs = 60000
): Promise<ResolveResponse> {
  const url = joinUrl(resolverBase, 'v1/resolve');
  let res: Response;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Authorization: `Bearer ${workloadToken}`,
      },
      body: JSON.stringify(req),
      signal: timeoutSignal(timeoutMs),
      redirect: 'manual',
    });
  } catch (e) {
    throw new ApiError(0, `network error contacting cloud resolver: ${e instanceof Error ? e.message : String(e)}`);
  }
  rejectRedirect(res.status);
  const text = await readCapped(res, MAX_RESPONSE_BYTES);
  if (res.status < 200 || res.status >= 300) {
    throw new ApiError(res.status, decodeError(res.status, text));
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new ApiError(res.status, 'cloud resolver returned non-JSON success body');
  }
  const m = json as Record<string, unknown>;
  // C4: an incomplete envelope (no valid status_code) is not a success. Falling
  // back to res.status would accept a resolver answer that omitted status_code
  // as a status-0 call. Require a number in the valid HTTP range.
  const statusCode = m['status_code'];
  if (typeof statusCode !== 'number' || !Number.isInteger(statusCode) || statusCode < 100 || statusCode > 599) {
    throw new ApiError(res.status, 'cloud resolver returned an incomplete envelope (missing a valid status_code)');
  }
  return {
    status_code: statusCode,
    headers: (m['headers'] as Record<string, string>) ?? {},
    body: typeof m['body'] === 'string' ? m['body'] : '',
    redacted: m['redacted'] === true,
  };
}

/** Cloud resolver liveness (public /healthz). Null body on failure. */
export async function cloudHealth(resolverBase: string, timeoutMs = 5000): Promise<unknown | null> {
  try {
    const res = await fetch(joinUrl(resolverBase, 'healthz'), { signal: timeoutSignal(timeoutMs) });
    if (!res.ok) return null;
    try {
      return await res.json();
    } catch {
      return null;
    }
  } catch {
    return null;
  }
}
