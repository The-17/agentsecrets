/**
 * Per-call orchestrator: mode + credentials + project context, resolved
 * fresh on every tool call (the server is long-lived; logins, installs,
 * and project switches happen mid-session).
 */

import { resolveMode } from '../mode.js';
import { resolveCredentials } from '../auth/chain.js';
import { resolveContext, NoContextError, type ContextInput } from '../context.js';
import { resolveServer, resolveProxyPort, resolveEnvironment } from '../auth/cliFiles.js';
import { controlCall } from './client.js';
import { needJwt } from './guards.js';
import type { Ctx, ModeResolution, ServerTarget } from './types.js';

export interface CallCtx {
  mode: ModeResolution;
  creds: Awaited<ReturnType<typeof resolveCredentials>>;
  ctx: Ctx;
  /** Directory to spawn the local helper in. */
  dir: string;
  server: ServerTarget;
  resolverBase: string;
}

export function resolverBaseUrl(): string {
  // The cloud resolver is its own host (control plane has no /v1/* routes).
  // Verified live: resolver.agentsecrets.tech/healthz → 200, while
  // api.agentsecrets.tech/{healthz,v1/resolve} → 404.
  const raw =
    process.env['AGENTSECRETS_CLOUD_RESOLVER_URL']?.trim() || 'https://resolver.agentsecrets.tech';
  return raw.replace(/\/+$/, '');
}

export async function resolveCallCtx(input: ContextInput, cwd: string): Promise<CallCtx> {
  const mode = resolveMode();
  const server = resolveServer(cwd);

  // Workspace-first credential pass: explicit workspace param lets the
  // pinned identity resolve without a project lookup.
  const workspaceHint = input.workspace ?? process.env['AGENTSECRETS_WORKSPACE']?.trim() ?? undefined;
  const creds = await resolveCredentials({ workspaceId: workspaceHint });

  const cloudGet =
    mode.mode === 'cloud' && creds.token && creds.tokenKind === 'jwt'
      ? (key: string, urlParams?: Record<string, string>) =>
          controlCall(server.url, creds.token as string, key, 'GET', { urlParams }).then((r) => r.data)
      : null;

  const { ctx, dir } = await (async () => {
    try {
      return await resolveContext(input, { cwd, mode: mode.mode, cloudGet });
    } catch (e) {
      // Context-optional tools (auth_status, proxy_status, ...) must work
      // with zero configuration. Only tolerate a COMPLETELY empty context;
      // explicit-but-unresolvable references always fail loudly.
      const explicit =
        input.project || input.workspace || input.path ||
        process.env['AGENTSECRETS_PROJECT'] || process.env['AGENTSECRETS_WORKSPACE'];
      if (explicit || !(e instanceof NoContextError)) throw e;
      return {
        ctx: {
          projectId: null,
          projectName: null,
          workspaceId: null,
          workspaceName: null,
          environment: resolveEnvironment(cwd).name,
          source: 'none',
        },
        dir: null as string | null,
      };
    }
  })();

  // Second pass: pinned identity for the resolved workspace.
  if (ctx.workspaceId && !creds.agentToken) {
    const again = await resolveCredentials({ workspaceId: ctx.workspaceId });
    if (again.agentToken) creds.agentToken = again.agentToken;
    if (!creds.workspaceKey && again.workspaceKey) {
      creds.workspaceKey = again.workspaceKey;
      creds.workspaceKeySource = again.workspaceKeySource;
    }
  }

  return {
    mode,
    creds,
    ctx: {
      creds,
      server,
      env: { name: ctx.environment, source: ctx.source },
      project: ctx.projectId
        ? {
            projectId: ctx.projectId,
            projectName: ctx.projectName ?? '',
            workspaceId: ctx.workspaceId ?? '',
            workspaceName: ctx.workspaceName ?? '',
            source: ctx.source as 'project.json' | 'global config',
          }
        : null,
      proxyPort: resolveProxyPort(),
      cwd,
    },
    dir: dir ?? cwd,
    server,
    resolverBase: resolverBaseUrl(),
  };
}

/** Control-plane GET bound to this call (throws the JWT guard when missing). */
export function callControl(call: CallCtx) {
  const token = needJwt(call.creds);
  const base = call.server.url;
  return {
    get: (key: string, urlParams?: Record<string, string>, query?: Record<string, string>) =>
      controlCall(base, token, key, 'GET', { urlParams, query }).then((r) => r.data),
    post: (key: string, body?: unknown, urlParams?: Record<string, string>) =>
      controlCall(base, token, key, 'POST', { body, urlParams }).then((r) => r.data),
    patch: (key: string, body?: unknown, urlParams?: Record<string, string>) =>
      controlCall(base, token, key, 'PATCH', { body, urlParams }).then((r) => r.data),
    del: (key: string, urlParams?: Record<string, string>) =>
      controlCall(base, token, key, 'DELETE', { urlParams }).then((r) => r.data),
  };
}
