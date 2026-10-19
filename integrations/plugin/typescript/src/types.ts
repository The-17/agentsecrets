import { InvalidRequest } from "./errors.js";

export const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
export type Method = (typeof METHODS)[number];

export const ENVIRONMENTS = ["development", "staging", "production"] as const;
export type Environment = (typeof ENVIRONMENTS)[number];

const TARGETED_STYLES = new Set(["header", "query", "body", "form"]);
const UNTARGETED_STYLES = new Set(["bearer", "basic"]);

export interface Scope {
  workspace_id?: string;
  project_id?: string;
}

export interface CallRequest {
  url: string;
  injections: Record<string, string>;
  method?: Method | string;
  headers?: Record<string, string>;
  body?: string;
  environment?: Environment | string;
  path?: string;
  agent_id?: string;
  agentId?: string;
  scope?: Scope;
}

export interface NormalizedCallRequest {
  url: string;
  injections: Record<string, string>;
  method: Method;
  headers: Record<string, string>;
  body?: string;
  environment?: Environment;
  path?: string;
  agent_id: string;
  scope?: Scope;
}

export interface Injection {
  style: string;
  target: string;
  key: string;
}

export interface CallResult {
  status_code: number;
  headers: Record<string, string>;
  body: string;
  environment?: string;
  redacted?: boolean;
}

export interface Transport {
  call(request: NormalizedCallRequest): Promise<CallResult>;
}

export function parseInjections(raw: Record<string, string>): Injection[] {
  const entries = Object.entries(raw);
  if (entries.length === 0) {
    throw new InvalidRequest("injections must contain at least one entry");
  }

  return entries.map(([spec, key]) => {
    if (typeof key !== "string" || key.trim() === "") {
      throw new InvalidRequest("injection key name must not be empty");
    }
    if (key !== key.trim()) {
      throw new InvalidRequest("injection key name must not contain surrounding whitespace");
    }

    const colon = spec.indexOf(":");
    const style = (colon === -1 ? spec : spec.slice(0, colon)).trim().toLowerCase();
    const target = colon === -1 ? "" : spec.slice(colon + 1).trim();

    if (UNTARGETED_STYLES.has(style)) {
      if (colon !== -1) {
        throw new InvalidRequest(`${style} injection does not take a target`);
      }
    } else if (TARGETED_STYLES.has(style)) {
      if (!target) {
        throw new InvalidRequest(`${style} injection requires a target, for example ${style}:name`);
      }
    } else {
      throw new InvalidRequest(
        `unknown injection style ${JSON.stringify(spec)}. Valid styles: bearer, basic, ` +
          "header:name, query:param, body:path, form:field",
      );
    }

    return { style, target, key };
  });
}

export function normalizeRequest(input: CallRequest | Record<string, unknown>): NormalizedCallRequest {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new InvalidRequest("request must be an object");
  }
  const raw = input as Record<string, unknown>;

  if (typeof raw.url !== "string" || raw.url.trim() === "") {
    throw new InvalidRequest("url is required");
  }
  if (typeof raw.injections !== "object" || raw.injections === null || Array.isArray(raw.injections)) {
    throw new InvalidRequest("injections must be an object");
  }
  const injections: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw.injections as Record<string, unknown>)) {
    if (typeof value !== "string") {
      throw new InvalidRequest("injections must map string specs to string key names");
    }
    injections[key] = value;
  }
  const parsedInjections = parseInjections(injections);
  const normalizedInjections: Record<string, string> = {};
  for (const injection of parsedInjections) {
    const spec = injection.style + (injection.target ? `:${injection.target}` : "");
    normalizedInjections[spec] = injection.key;
  }

  const methodValue = raw.method === undefined ? "GET" : raw.method;
  if (typeof methodValue !== "string") {
    throw new InvalidRequest("method must be a string");
  }
  const method = methodValue.toUpperCase();
  if (!METHODS.includes(method as Method)) {
    throw new InvalidRequest("method must be one of " + METHODS.join(", "));
  }

  const headers: Record<string, string> = {};
  if (raw.headers !== undefined) {
    if (typeof raw.headers !== "object" || raw.headers === null || Array.isArray(raw.headers)) {
      throw new InvalidRequest("headers must be an object");
    }
    for (const [key, value] of Object.entries(raw.headers as Record<string, unknown>)) {
      if (typeof value !== "string") {
        throw new InvalidRequest("headers must map string names to string values");
      }
      headers[key] = value;
    }
  }

  const body = raw.body;
  if (body !== undefined && typeof body !== "string") {
    throw new InvalidRequest("body must be a string");
  }

  const environmentValue = raw.environment;
  if (environmentValue !== undefined && environmentValue !== null) {
    if (typeof environmentValue !== "string" || !ENVIRONMENTS.includes(environmentValue as Environment)) {
      throw new InvalidRequest("environment must be development, staging, or production");
    }
  }

  const path = raw.path;
  if (path !== undefined && typeof path !== "string") {
    throw new InvalidRequest("path must be a string");
  }

  const agentValue = raw.agent_id ?? raw.agentId ?? "plugin";
  if (typeof agentValue !== "string" || agentValue.trim() === "") {
    throw new InvalidRequest("agent_id must be a non-empty string");
  }

  let scope: Scope | undefined;
  if (raw.scope !== undefined && raw.scope !== null) {
    if (typeof raw.scope !== "object" || Array.isArray(raw.scope)) {
      throw new InvalidRequest("scope must be an object");
    }
    const rawScope = raw.scope as Record<string, unknown>;
    const workspace = rawScope.workspace_id ?? rawScope.workspaceId;
    const project = rawScope.project_id ?? rawScope.projectId;
    const nextScope: Scope = {};
    if (workspace !== undefined) {
      if (typeof workspace !== "string") {
        throw new InvalidRequest("scope.workspace_id must be a string");
      }
      nextScope.workspace_id = workspace;
    }
    if (project !== undefined) {
      if (typeof project !== "string") {
        throw new InvalidRequest("scope.project_id must be a string");
      }
      nextScope.project_id = project;
    }
    scope = nextScope;
  }

  const normalized: NormalizedCallRequest = {
    url: raw.url,
    injections: normalizedInjections,
    method: method as Method,
    headers,
    agent_id: agentValue,
    ...(body !== undefined ? { body } : {}),
    ...(environmentValue !== undefined && environmentValue !== null
      ? { environment: environmentValue as Environment }
      : {}),
    ...(path !== undefined ? { path } : {}),
    ...(scope !== undefined ? { scope } : {}),
  };
  return normalized;
}

export function prepareRequest(request: NormalizedCallRequest): NormalizedCallRequest {
  const hasContentType = Object.keys(request.headers).some((key) => key.toLowerCase() === "content-type");
  if (!request.body || hasContentType) {
    return request;
  }

  try {
    JSON.parse(request.body);
  } catch {
    return request;
  }

  return {
    ...request,
    headers: { ...request.headers, "Content-Type": "application/json" },
  };
}

export function localPayload(request: NormalizedCallRequest): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    url: request.url,
    method: request.method,
    injections: request.injections,
    agent_id: request.agent_id,
  };
  if (Object.keys(request.headers).length > 0) {
    payload.headers = request.headers;
  }
  if (request.body !== undefined) {
    payload.body = request.body;
  }
  if (request.environment !== undefined) {
    payload.environment = request.environment;
  }
  if (request.path !== undefined) {
    payload.path = request.path;
  }
  return payload;
}

export function resultToDict(result: CallResult): Record<string, unknown> {
  const out: Record<string, unknown> = {
    status_code: result.status_code,
    headers: result.headers,
    body: result.body,
  };
  if (result.environment !== undefined) {
    out.environment = result.environment;
  }
  if (result.redacted !== undefined) {
    out.redacted = result.redacted;
  }
  return out;
}
