/**
 * Shared types for the AgentSecrets MCP bridge.
 *
 * Backend model (mirrors the real deployments — see pkg/api, pkg/proxy,
 * pkg/config in the Go CLI):
 *
 * - Local proxy: the CLI's `agentsecrets proxy start` daemon on
 *   127.0.0.1:<port> speaking the X-AS-* header protocol (POST /proxy,
 *   GET /health). Credentialed API calls, zero values at the tool boundary.
 * - Control plane: the AgentSecrets API (default
 *   https://api.agentsecrets.tech/api, or self-hosted via
 *   AGENTSECRETS_SERVER_URL). User-JWT Bearer auth. Management + metadata.
 *
 * - Cloud resolver (agentsecrets-cloud): POST /v1/resolve for credentialed
 *   calls. Auth: a workload credential — the raw token secret (verified by
 *   hash) or an agt_ identifier (verified by id match). Referenced secrets
 *   arrive as {{KEY}} handles and are substituted server-side; only the
 *   sanitized upstream response returns. POST /api/workloads/env/ returns
 *   secret VALUES, so the bridge never calls it.
 */

export type TokenKind = 'jwt' | 'workload';

export interface Credentials {
  /** User JWT / service credential, or a workload credential (raw secret or agt_ id). Never logged. */
  token: string | null;
  tokenKind: TokenKind | null;
  /** Non-secret provenance label, e.g. "AGENTSECRETS_TOKEN", "AGENTSECRETS_TOKEN_FILE". */
  tokenSource: string | null;
  /** Issued agent identity for proxy audit attribution (AS_AGENT_TOKEN, ...). Never logged. */
  agentToken: string | null;
  /** Declared agent identity forwarded as X-AS-Agent-ID. */
  agentId: string | null;
  /** Local proxy session token (X-AS-Session-Token). Never logged. */
  sessionToken: string | null;
  /** 32-byte workspace data key for AES-256-GCM secret ops. Never logged. */
  workspaceKey: Buffer | null;
  /** Non-secret provenance label for the workspace key. */
  workspaceKeySource: string | null;
}

export interface ServerTarget {
  url: string;
  /** "AGENTSECRETS_SERVER_URL" | "AGENTSECRETS_API_URL" | "project.json" | "global config" | "default" */
  source: string;
}

export interface EnvTarget {
  name: string;
  source: string;
}

export interface ProjectRef {
  projectId: string;
  projectName: string;
  workspaceId: string;
  workspaceName: string;
  /** "project.json" | "global config" */
  source: string;
}

/** Per-tool-call context. Resolved fresh on every call (long-lived process). */
export interface Ctx {
  creds: Credentials;
  server: ServerTarget;
  env: EnvTarget;
  project: ProjectRef | null;
  /** Proxy port from PID file / env. Null when unknown. Liveness is probed per call. */
  proxyPort: number | null;
  cwd: string;
}

export interface ProxyHealth {
  status: string;
  project?: string;
  last_sync?: string;
  revoked_count?: number;
  revoked_ids?: string[];
}

/** MCP tool text result. Values MUST never appear in `text`. */
export interface ToolResult {
  [x: string]: unknown;
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

export function ok(payload: unknown): ToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] };
}

export function okText(text: string): ToolResult {
  return { content: [{ type: 'text', text }] };
}

export function fail(message: string): ToolResult {
  return { isError: true, content: [{ type: 'text', text: message }] };
}

export const VALID_ENVIRONMENTS = ['development', 'staging', 'production'] as const;
export type Environment = (typeof VALID_ENVIRONMENTS)[number];

export function isValidEnvironment(v: string): v is Environment {
  return (VALID_ENVIRONMENTS as readonly string[]).includes(v);
}

/** One pinned workload identity: an agent registration + a bridge-owned token. */
export interface PinnedIdentity {
  registration_id: string;
  agent_name: string;
  /** Raw workload token secret issued for the bridge (NOT the agt_ id). Never logged, 0600 file only. */
  token: string;
  label: string;
  pinned_at: string;
  /** Scope triple bound to the token server-side (resolution is exact-triple). */
  workspace_id: string;
  project_id: string | null;
  environment: string | null;
  scope_source: 'registration';
  /** Set when the registration is workspace-wide: /v1/resolve looks up an exact project and may find nothing. */
  resolve_may_be_empty?: boolean;
}

export interface OAuthTokens {
  access_token: string;
  refresh_token: string | null;
  expires_at: string | null;
  token_url: string;
  client_id: string;
}

/** Bridge-owned session: OAuth login + per-workspace identities + defaults. */
export interface BridgeSession {
  oauth: OAuthTokens | null;
  identities: Record<string, PinnedIdentity>;
  defaults: {
    workspace_id: string | null;
    project_id: string | null;
    project_name: string | null;
  };
}

export function emptySession(): BridgeSession {
  return { oauth: null, identities: {}, defaults: { workspace_id: null, project_id: null, project_name: null } };
}

/** Resolved per-call project context. Echoed in every tool result. */
export interface ResolvedContext {
  projectId: string | null;
  projectName: string | null;
  workspaceId: string | null;
  workspaceName: string | null;
  environment: string;
  /** explicit | path | env | cwd | pinned | none */
  source: string;
}

export type BridgeMode = 'local' | 'cloud';

export interface ModeResolution {
  mode: BridgeMode;
  binary: string | null;
  bridgeVersion: string | null;
  reason: string;
}
