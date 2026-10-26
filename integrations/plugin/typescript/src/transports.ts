import { spawnSync } from "node:child_process";

import { buildChildEnv } from "./env.js";
import {
  AuthenticationError,
  AuthorizationError,
  ConfigurationError,
  InvalidRequest,
  QuotaExceededError,
  TransportError,
  UnsupportedInjection,
} from "./errors.js";
import type { CallResult, NormalizedCallRequest } from "./types.js";
import { localPayload, parseInjections, prepareRequest } from "./types.js";

const TOKEN_PATTERN = /\bagt_[A-Za-z0-9._-]{8,}\b/g;

function sanitize(text: string, token?: string): string {
  const withoutToken = token ? text.split(token).join("[REDACTED]") : text;
  return withoutToken.replace(TOKEN_PATTERN, "[REDACTED]");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function joinHeaders(value: unknown): Record<string, string> {
  if (!isRecord(value)) {
    return {};
  }
  const headers: Record<string, string> = {};
  for (const [key, raw] of Object.entries(value)) {
    if (Array.isArray(raw)) {
      headers[key] = raw.map((item) => String(item)).join(", ");
    } else {
      headers[key] = String(raw);
    }
  }
  return headers;
}

export interface LocalHelperOptions {
  binary: string;
  args?: string[];
  statusArgs?: string[];
  timeoutMs?: number;
  cwd?: string;
  env?: Record<string, string>;
}

export class LocalHelperTransport {
  private readonly binary: string;
  private readonly args: string[];
  private readonly statusArgs: string[];
  private readonly timeoutMs: number;
  private readonly cwd: string | undefined;
  private readonly env: Record<string, string>;
  private readonly environmentCache = new Map<string, { value: string; at: number }>();

  constructor(options: LocalHelperOptions) {
    this.binary = options.binary;
    this.args = options.args ?? ["mcp", "proxy.call"];
    this.statusArgs = options.statusArgs ?? ["mcp", "status"];
    this.timeoutMs = options.timeoutMs ?? 60_000;
    this.cwd = options.cwd;
    this.env = options.env ?? {};
  }

  private run(
    args: string[],
    input: string,
    cwd: string | undefined,
    timeoutMs: number,
  ): Record<string, unknown> {
    const completed = spawnSync(this.binary, args, {
      input,
      encoding: "utf8",
      timeout: timeoutMs,
      env: buildChildEnv(this.env),
      windowsHide: true,
      maxBuffer: 10 * 1024 * 1024,
      ...(cwd !== undefined ? { cwd } : {}),
    });

    if (completed.error) {
      const code = (completed.error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") {
        throw new ConfigurationError(`agentsecrets binary not found at ${this.binary}`);
      }
      if (code === "ETIMEDOUT") {
        throw new TransportError("agentsecrets helper timed out");
      }
      throw new TransportError(sanitize(completed.error.message));
    }

    const stdout = (completed.stdout ?? "").trim();
    const stderr = (completed.stderr ?? "").trim();
    if (completed.status !== 0 && stdout === "") {
      throw new TransportError(
        sanitize(`agentsecrets helper exited ${completed.status ?? "unknown"}: ${stderr.slice(-500)}`),
      );
    }

    let envelope: unknown;
    try {
      envelope = JSON.parse(stdout || "{}");
    } catch {
      throw new TransportError(
        sanitize(`agentsecrets helper returned non-JSON stdout: ${stderr.slice(-300)}`),
      );
    }
    if (!isRecord(envelope) || typeof envelope.ok !== "boolean") {
      throw new TransportError("agentsecrets helper returned a malformed envelope");
    }
    if (!envelope.ok) {
      const message = envelope.error;
      throw new TransportError(
        sanitize(typeof message === "string" ? message : "agentsecrets helper failed"),
      );
    }

    const data = envelope.data;
    if (!isRecord(data)) {
      throw new TransportError("agentsecrets helper returned no data");
    }
    return data;
  }

  async call(request: NormalizedCallRequest): Promise<CallResult> {
    const prepared = prepareRequest(request);
    const data = this.run(
      this.args,
      JSON.stringify(localPayload(prepared)),
      prepared.path ?? this.cwd,
      this.timeoutMs,
    );
    if (typeof data.status_code !== "number" || typeof data.body !== "string") {
      throw new TransportError("agentsecrets helper returned an invalid result");
    }

    const environment = typeof data.environment === "string" ? data.environment : undefined;
    return {
      status_code: data.status_code,
      headers: joinHeaders(data.headers),
      body: data.body,
      ...(environment !== undefined ? { environment } : {}),
    };
  }

  activeEnvironment(cwd?: string): string {
    const effectiveCwd = cwd ?? this.cwd;
    const cacheKey = effectiveCwd ?? "";
    const cached = this.environmentCache.get(cacheKey);
    if (cached !== undefined && Date.now() - cached.at < 60_000) {
      return cached.value;
    }

    const data = this.run(
      this.statusArgs,
      "{}",
      effectiveCwd,
      Math.min(this.timeoutMs, 15_000),
    );
    const environment = data.environment;
    if (!isRecord(environment) || typeof environment.active !== "string") {
      throw new TransportError(
        "agentsecrets helper does not report its active environment. Upgrade the CLI.",
      );
    }
    const active = environment.active;
    this.environmentCache.set(cacheKey, { value: active, at: Date.now() });
    return active;
  }
}

export interface CloudResolverOptions {
  token: string;
  resolverUrl?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export class CloudResolverTransport {
  private readonly token: string;
  private readonly resolverUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: CloudResolverOptions) {
    this.token = options.token;
    this.resolverUrl = (options.resolverUrl ?? "https://resolver.agentsecrets.tech").replace(/\/+$/, "");
    this.timeoutMs = options.timeoutMs ?? 60_000;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async call(request: NormalizedCallRequest): Promise<CallResult> {
    const payload = buildResolvePayload(request);
    let response: Response;
    try {
      response = await this.fetchImpl(this.resolverUrl + "/v1/resolve", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new TransportError(`cloud resolver unreachable: ${sanitize(message, this.token)}`);
    }

    const text = await response.text();
    if (!response.ok) {
      const detail = sanitize(readDetail(text), this.token);
      if (response.status === 401) {
        throw new AuthenticationError("cloud resolver rejected the workload token");
      }
      if (response.status === 403) {
        throw new AuthorizationError(detail || "cloud resolver denied the request");
      }
      if (response.status === 429) {
        throw new QuotaExceededError(detail || "cloud resolver quota exceeded");
      }
      throw new TransportError(detail || `cloud resolver returned HTTP ${response.status}`);
    }

    let decoded: unknown;
    try {
      decoded = JSON.parse(text);
    } catch {
      throw new TransportError("cloud resolver returned non-JSON");
    }
    if (!isRecord(decoded) || typeof decoded.status_code !== "number" || typeof decoded.body !== "string") {
      throw new TransportError("cloud resolver returned an invalid result");
    }

    const redacted = typeof decoded.redacted === "boolean" ? decoded.redacted : undefined;
    return {
      status_code: decoded.status_code,
      headers: joinHeaders(decoded.headers),
      body: decoded.body,
      ...(request.environment !== undefined ? { environment: request.environment } : {}),
      ...(redacted !== undefined ? { redacted } : {}),
    };
  }
}

export function buildResolvePayload(request: NormalizedCallRequest): Record<string, unknown> {
  let parsed: URL;
  try {
    parsed = new URL(request.url);
  } catch {
    throw new InvalidRequest("url must be an absolute https:// URL");
  }
  if (parsed.protocol !== "https:") {
    throw new InvalidRequest("cloud mode requires an https:// target URL");
  }

  const prepared = prepareRequest(request);
  const headers: Record<string, string> = { ...prepared.headers };
  let body = prepared.body ?? "";

  for (const injection of parseInjections(prepared.injections)) {
    const handle = `{{${injection.key}}}`;
    if (injection.style === "bearer") {
      headers.Authorization = "Bearer " + handle;
    } else if (injection.style === "header") {
      headers[injection.target] = handle;
    } else if (injection.style === "body") {
      let parsedBody: unknown;
      try {
        parsedBody = body ? JSON.parse(body) : {};
      } catch {
        throw new InvalidRequest("body injection requires a JSON object body");
      }
      if (!isRecord(parsedBody)) {
        throw new InvalidRequest("body injection requires a JSON object body");
      }
      setPath(parsedBody, injection.target, handle);
      body = JSON.stringify(parsedBody);
      ensureContentType(headers, "application/json");
    } else if (injection.style === "form") {
      const params = new URLSearchParams(body);
      params.set(injection.target, handle);
      body = params.toString();
      ensureContentType(headers, "application/x-www-form-urlencoded");
    } else {
      throw new UnsupportedInjection(
        `${injection.style} injection is not expressible in cloud mode. ` +
          "Use local mode, which has the CLI and keychain.",
      );
    }
  }

  const payload: Record<string, unknown> = {
    target_url: request.url,
    method: request.method,
    headers,
    body,
  };

  const scope: Record<string, string> = {};
  if (request.scope?.workspace_id !== undefined) {
    scope.workspace_id = request.scope.workspace_id;
  }
  if (request.scope?.project_id !== undefined) {
    scope.project_id = request.scope.project_id;
  }
  if (request.environment !== undefined) {
    scope.environment = request.environment;
  }
  if (Object.keys(scope).length > 0) {
    payload.scope = scope;
  }
  return payload;
}

function setPath(object: Record<string, unknown>, dotted: string, value: string): void {
  const parts = dotted.split(".").filter((part) => part.length > 0);
  if (parts.length === 0) {
    throw new InvalidRequest("body injection requires a non-empty JSON path");
  }

  let cursor: Record<string, unknown> = object;
  for (const part of parts.slice(0, -1)) {
    const current = cursor[part];
    if (!isRecord(current)) {
      const next: Record<string, unknown> = {};
      cursor[part] = next;
      cursor = next;
    } else {
      cursor = current;
    }
  }
  const last = parts[parts.length - 1];
  if (last === undefined) {
    throw new InvalidRequest("body injection requires a non-empty JSON path");
  }
  cursor[last] = value;
}

function ensureContentType(headers: Record<string, string>, value: string): void {
  if (!Object.keys(headers).some((key) => key.toLowerCase() === "content-type")) {
    headers["Content-Type"] = value;
  }
}

function readDetail(text: string): string {
  try {
    const decoded: unknown = JSON.parse(text);
    if (isRecord(decoded)) {
      for (const key of ["error", "message", "detail"]) {
        const value = decoded[key];
        if (typeof value === "string" && value) {
          return value.slice(0, 500);
        }
      }
    }
  } catch {
    // Fall through to raw text.
  }
  return text.slice(0, 500);
}
