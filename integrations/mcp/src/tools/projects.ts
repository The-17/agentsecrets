/**
 * Project tools. Local mode delegates to the CLI helper (which also binds
 * .agentsecrets/project.json). Cloud mode calls the control plane and pins
 * session defaults + syncs a local project.json when one exists.
 */

import { z } from 'zod';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { CallCtx } from '../resolver/index.js';
import { callControl } from '../resolver/index.js';
import { fail, type ToolResult } from '../resolver/types.js';
import { dispatch, resolveWorkspaceId, withContext } from './common.js';
import { needJwt } from '../resolver/guards.js';
import { loadProjectConfig, saveProjectConfig, loadGlobalConfig } from '../auth/cliFiles.js';
import { loadSession, saveSession } from '../auth/session.js';

const contextFields = {
  workspace: z.string().optional().describe('Workspace name or ID (defaults to current context)'),
  path: z.string().optional().describe('Project directory holding .agentsecrets/project.json'),
};

export const projectListSchema = z.object({ ...contextFields });
export type ProjectListArgs = z.infer<typeof projectListSchema>;

export const projectCreateSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  ...contextFields,
});
export type ProjectCreateArgs = z.infer<typeof projectCreateSchema>;

export const projectUseSchema = z.object({
  name: z.string().min(1).describe('Project name to select and bind locally'),
  ...contextFields,
});
export type ProjectUseArgs = z.infer<typeof projectUseSchema>;

export const projectUpdateSchema = z.object({
  name: z.string().min(1).describe('Current project name'),
  newName: z.string().optional(),
  description: z.string().optional(),
  ...contextFields,
});
export type ProjectUpdateArgs = z.infer<typeof projectUpdateSchema>;

export const projectDeleteSchema = z.object({
  name: z.string().min(1),
  ...contextFields,
  confirm: z.literal(true).describe('Required: acknowledges permanent deletion'),
});
export type ProjectDeleteArgs = z.infer<typeof projectDeleteSchema>;

interface ProjectShape {
  id: string;
  name: string;
  description?: string;
  workspace_id: string;
}

/** Mirror Go bindLocally: persist selection to project.json + session defaults. */
function bindProject(call: CallCtx, proj: ProjectShape): void {
  const session = loadSession();
  saveSession({
    ...session,
    defaults: { workspace_id: proj.workspace_id, project_id: proj.id, project_name: proj.name },
  });
  const loaded = loadProjectConfig(call.dir);
  if (loaded) {
    const g = loadGlobalConfig();
    saveProjectConfig(call.dir, {
      ...loaded.config,
      project_id: proj.id,
      project_name: proj.name,
      description: proj.description ?? loaded.config.description ?? '',
      workspace_id: proj.workspace_id,
      workspace_name: g?.workspaces?.[proj.workspace_id]?.name ?? loaded.config.workspace_name ?? '',
    });
  }
}

function unbindProject(call: CallCtx, name: string, wsId: string): void {
  const loaded = loadProjectConfig(call.dir);
  if (loaded && (loaded.config.project_name === name || loaded.config.project_id === name) && (!loaded.config.workspace_id || loaded.config.workspace_id === wsId)) {
    try {
      const file = path.join(call.dir, '.agentsecrets', 'project.json');
      fs.rmSync(file, { force: true });
    } catch {
      /* best effort */
    }
  }
  const session = loadSession();
  if (session.defaults.project_name === name || session.defaults.project_id === name) {
    saveSession({ ...session, defaults: { ...session.defaults, project_id: null, project_name: null } });
  }
}

export async function projectList(call: CallCtx, args: ProjectListArgs): Promise<ToolResult> {
  return dispatch(call, 'project.list', { ...args }, async () => {
    needJwt(call.creds);
    const list = (await callControl(call).get('projects.list')) as ProjectShape[];
    const current = call.ctx.project?.projectId;
    return withContext(call, {
      projects: (list ?? []).map((p) => ({ ...p, selected: current ? p.id === current : false })),
    });
  });
}

export async function projectCreate(call: CallCtx, args: ProjectCreateArgs): Promise<ToolResult> {
  if (!args.name.trim()) return fail('missing required parameter: name');
  return dispatch(call, 'project.create', { ...args }, async () => {
    needJwt(call.creds);
    const wsId = await resolveWorkspaceId(call, args.workspace);
    const body: Record<string, string> = { name: args.name, workspace_id: wsId };
    if (args.description) body['description'] = args.description;
    const proj = (await callControl(call).post('projects.create', body)) as ProjectShape;
    bindProject(call, proj);
    return withContext(call, { status: 'success', project: proj });
  });
}

export async function projectUse(call: CallCtx, args: ProjectUseArgs): Promise<ToolResult> {
  return dispatch(call, 'project.use', { ...args }, async () => {
    needJwt(call.creds);
    const wsId = await resolveWorkspaceId(call, args.workspace);
    const proj = (await callControl(call).get('projects.get', { workspace_id: wsId, project_name: args.name })) as ProjectShape;
    bindProject(call, proj);
    return withContext(call, { status: 'success', project: proj });
  });
}

export async function projectUpdate(call: CallCtx, args: ProjectUpdateArgs): Promise<ToolResult> {
  if (!args.newName && !args.description) return fail('nothing to update: provide newName and/or description');
  return dispatch(call, 'project.update', { ...args }, async () => {
    needJwt(call.creds);
    const wsId = await resolveWorkspaceId(call, args.workspace);
    const payload: Record<string, string> = {};
    if (args.newName) payload['name'] = args.newName;
    if (args.description) payload['description'] = args.description;
    await callControl(call).patch('projects.update', payload, { workspace_id: wsId, project_name: args.name });
    const loaded = loadProjectConfig(call.dir);
    if (loaded && loaded.config.project_name === args.name && (!loaded.config.workspace_id || loaded.config.workspace_id === wsId)) {
      saveProjectConfig(call.dir, {
        ...loaded.config,
        project_name: args.newName ?? loaded.config.project_name,
        description: args.description ?? loaded.config.description ?? '',
      });
    }
    return withContext(call, { status: 'success', name: args.newName ?? args.name });
  });
}

export async function projectDelete(call: CallCtx, args: ProjectDeleteArgs): Promise<ToolResult> {
  return dispatch(call, 'project.delete', { ...args, confirm: true }, async () => {
    needJwt(call.creds);
    const wsId = await resolveWorkspaceId(call, args.workspace);
    await callControl(call).del('projects.delete', { workspace_id: wsId, project_name: args.name });
    unbindProject(call, args.name, wsId);
    return withContext(call, { status: 'success', name: args.name });
  });
}

export const projectDescriptions = {
  project_list:
    'See all projects you can access, with the currently active one marked. ' +
    'WHEN: you need a project name or ID for another tool, or the human asks what projects exist.',
  project_create:
    'Create a new project (a named bucket of secrets for one application) and make it the active one. ' +
    'WHEN: the human explicitly asks for a new project. Always confirm the exact name in chat first.',
  project_use:
    'Switch which project later calls act on, by name. ' +
    'WHEN: the human says "use project X" or work moves to a different codebase. This rewrites local binding + defaults — confirm first.',
  project_update:
    'Rename a project or change its description. WHEN: the human asks to rename or document a project.',
  project_delete:
    'Permanently delete a project and ALL its secrets in every environment. ' +
    'WHEN: only on the human\u2019s explicit, specific request. Requires confirm:true AND human approval in chat — never infer consent.',
};
