/**
 * Per-call project context. One bridge install serves ALL of the user's
 * projects — the active scope is resolved fresh on every tool call:
 *
 *   1. explicit `project` / `workspace` params (always win)
 *   2. `path` param -> that directory's .agentsecrets/project.json
 *   3. AGENTSECRETS_PROJECT / AGENTSECRETS_WORKSPACE env hints (SDK parity)
 *   4. cwd walk-up .agentsecrets/project.json (in-codebase agents)
 *   5. pinned session defaults (auth_use_identity / project_use / workspace_switch)
 *   6. otherwise a guided NoContext error (pure-cloud chats: the LLM asks
 *      the human, then passes explicit params or pins defaults)
 *
 * Name -> ID mapping in cloud mode uses the control-plane API (needs the
 * management JWT). In local mode, workspace names map via the offline
 * global-config cache and projects via project.json — pass `path` for any
 * directory other than the launch cwd.
 *
 * Every resolution is echoed back in tool results (`context` key) so the
 * model always sees which project/workspace/environment acted.
 */

import {
  loadGlobalConfig,
  loadProjectConfig,
  findProjectRoot,
  resolveEnvironment,
  type ProjectConfig,
} from './auth/cliFiles.js';
import { loadSession } from './auth/session.js';
import { isValidEnvironment, type ResolvedContext } from './resolver/types.js';

export class NoContextError extends Error {
  constructor(detail: string) {
    super(
      `No project context: ${detail}. Options: pass {project, workspace} explicitly, ` +
        `run from inside a project directory (with .agentsecrets/project.json), set ` +
        `AGENTSECRETS_PROJECT/AGENTSECRETS_WORKSPACE, or pin defaults via auth_use_identity.`
    );
    this.name = 'NoContextError';
  }
}

export interface ContextInput {
  project?: string | undefined;
  workspace?: string | undefined;
  path?: string | undefined;
  environment?: string | undefined;
}

export interface ContextDeps {
  cwd: string;
  mode: 'local' | 'cloud';
  /** Control-plane GET helper for cloud name->ID lookups (null when no JWT). */
  cloudGet: ((endpointKey: string, urlParams?: Record<string, string>) => Promise<unknown>) | null;
}

export interface ContextOut {
  ctx: ResolvedContext;
  /** Directory to spawn the local helper in (null in cloud mode). */
  dir: string | null;
}

function projectConfigToCtx(pc: ProjectConfig, source: string, environment: string): ResolvedContext {
  return {
    projectId: pc.project_id ?? null,
    projectName: pc.project_name ?? null,
    workspaceId: pc.workspace_id ?? null,
    workspaceName: pc.workspace_name ?? null,
    environment,
    source,
  };
}

function resolveEnv(input: ContextInput, pc: ProjectConfig | null): string {
  if (input.environment) {
    if (!isValidEnvironment(input.environment)) {
      throw new Error(`invalid environment ${JSON.stringify(input.environment)} — must be development|staging|production.`);
    }
    return input.environment;
  }
  if (process.env['AGENTSECRETS_ENV'] && isValidEnvironment(process.env['AGENTSECRETS_ENV'])) {
    return process.env['AGENTSECRETS_ENV'];
  }
  if (pc?.environment && isValidEnvironment(pc.environment)) return pc.environment;
  return resolveEnvironment(process.cwd()).name;
}

export async function resolveContext(input: ContextInput, deps: ContextDeps): Promise<ContextOut> {
  const { cwd, mode, cloudGet } = deps;

  // --- 1/2. explicit names or path -------------------------------------
  if (input.project || input.workspace) {
    if (mode === 'cloud') {
      if (!cloudGet) {
        throw new NoContextError('explicit project targeting needs a control-plane login (auth_login)');
      }
      const wsId = await resolveWorkspaceIdCloud(input.workspace, cloudGet);
      const proj = input.project
        ? await resolveProjectCloud(wsId, input.project, cloudGet)
        : { projectId: null as string | null, projectName: null as string | null };
      const environment = resolveEnv(input, null);
      return {
        ctx: {
          projectId: proj.projectId,
          projectName: proj.projectName,
          workspaceId: wsId,
          workspaceName: input.workspace ?? null,
          environment,
          source: 'explicit',
        },
        dir: null,
      };
    }
    // Local mode is a thin pipe to the CLI helper: this branch only decides
    // the spawn directory and echoes the binding for result context.
    // ALL scope enforcement lives in the helper (expect_* checks,
    // daemon-project check) — single point, no duplicated behavior.
    if (input.path) {
      const loaded = loadProjectConfig(input.path);
      if (!loaded) throw new NoContextError(`no .agentsecrets/project.json under ${input.path}`);
      const pc = loaded.config;
      if (!pc.project_id) throw new NoContextError(`project.json under ${input.path} has no project_id`);
      return { ctx: projectConfigToCtx(pc, 'path', resolveEnv(input, pc)), dir: loaded.root };
    }
    const local = loadProjectConfig(cwd);
    const root = findProjectRoot(cwd);
    if (local?.config.project_id) {
      return { ctx: projectConfigToCtx(local.config, 'cwd', resolveEnv(input, local.config)), dir: root ?? cwd };
    }
    // No binding here: the helper verbs fail clearly on their own when they
    // need one (unscoped verbs like status/ping/list proceed).
    return {
      ctx: {
        projectId: null,
        projectName: input.project ?? null,
        workspaceId: null,
        workspaceName: input.workspace ?? null,
        environment: resolveEnv(input, null),
        source: 'cwd (no binding)',
      },
      dir: cwd,
    };
  }

  if (input.path) {
    const loaded = loadProjectConfig(input.path);
    if (!loaded) throw new NoContextError(`no .agentsecrets/project.json under ${input.path}`);
    const pc = loaded.config;
    if (!pc.project_id) throw new NoContextError(`project.json under ${input.path} has no project_id`);
    return { ctx: projectConfigToCtx(pc, 'path', resolveEnv(input, pc)), dir: loaded.root };
  }

  // --- 3. env hints ------------------------------------------------------
  const hintProject = process.env['AGENTSECRETS_PROJECT']?.trim() || null;
  const hintWorkspace = process.env['AGENTSECRETS_WORKSPACE']?.trim() || null;
  if (hintProject || hintWorkspace) {
    const out = await resolveContext({ project: hintProject ?? undefined, workspace: hintWorkspace ?? undefined }, deps);
    out.ctx.source = 'env';
    return out;
  }

  // --- 4. cwd walk-up ------------------------------------------------------
  const local = loadProjectConfig(cwd);
  if (local?.config.project_id) {
    const root = findProjectRoot(cwd);
    return { ctx: projectConfigToCtx(local.config, 'cwd', resolveEnv(input, local.config)), dir: mode === 'local' ? (root ?? cwd) : null };
  }

  // --- 5. pinned defaults ----------------------------------------------------
  const session = loadSession();
  if (session.defaults.workspace_id || session.defaults.project_id) {
    const g = loadGlobalConfig();
    const ws = session.defaults.workspace_id ? g?.workspaces?.[session.defaults.workspace_id] : undefined;
    return {
      ctx: {
        projectId: session.defaults.project_id,
        projectName: session.defaults.project_name,
        workspaceId: session.defaults.workspace_id,
        workspaceName: ws?.name ?? null,
        environment: resolveEnv(input, null),
        source: 'pinned',
      },
      dir: mode === 'local' ? cwd : null,
    };
  }

  // --- 6. guided failure -------------------------------------------------------
  throw new NoContextError('no project.json found, no defaults pinned, and no explicit project given');
}

async function resolveWorkspaceIdCloud(
  ref: string | undefined,
  cloudGet: NonNullable<ContextDeps['cloudGet']>
): Promise<string> {
  const list = (await cloudGet('workspaces.list')) as Array<{ id: string; name: string }>;
  if (!ref) {
    if (list.length === 1 && list[0]) return list[0].id;
    throw new NoContextError(
      `multiple workspaces available (${list.map((w) => w.name).join(', ')}) — pass workspace explicitly`
    );
  }
  const hit = list.find((w) => w.id === ref || w.name === ref);
  if (!hit) throw new NoContextError(`workspace ${JSON.stringify(ref)} not found`);
  return hit.id;
}

async function resolveProjectCloud(
  workspaceId: string,
  ref: string,
  cloudGet: NonNullable<ContextDeps['cloudGet']>
): Promise<{ projectId: string | null; projectName: string | null }> {
  try {
    const proj = (await cloudGet('projects.get', { workspace_id: workspaceId, project_name: ref })) as {
      id: string;
      name: string;
    };
    return { projectId: proj.id, projectName: proj.name };
  } catch {
    // Fall back to scanning the project list (covers ID refs too).
    const list = (await cloudGet('projects.list')) as Array<{
      id: string;
      name: string;
      workspace_id: string;
    }>;
    const hit = list.find(
      (p) => (p.id === ref || p.name === ref) && (!workspaceId || p.workspace_id === workspaceId)
    );
    if (!hit) throw new NoContextError(`project ${JSON.stringify(ref)} not found`);
    return { projectId: hit.id, projectName: hit.name };
  }
}
