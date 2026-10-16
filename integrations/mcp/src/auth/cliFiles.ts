/**
 * Read-only access to the Go CLI's on-disk state. Mirrors pkg/config
 * (file layout, resolution order) WITHOUT depending on the OS keychain —
 * the keychain-auth daemon verifies caller binary identity at the kernel
 * level and rejects unregistered binaries, so this bridge never attempts
 * keychain access and never writes secrets to disk.
 *
 * Layout (pkg/config):
 *   ~/.agentsecrets/config.json   email, server_url, selected workspace/
 *                                  project/environment, workspace metadata
 *                                  (keys stripped after keychain migration)
 *   ~/.agentsecrets/token.json    legacy JWT store (kept empty after
 *                                  migration; honored if populated)
 *   ~/.agentsecrets/proxy.pid     "pid\nstart_unix\nport" of running proxy
 *   ./.agentsecrets/project.json  project binding (walk up from cwd)
 *
 * AGENTSECRETS_HOME overrides the home directory (tests, containers).
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { normalizeServerUrl, DEFAULT_BASE_URL } from '../resolver/endpoints.js';
import { isValidEnvironment } from '../resolver/types.js';

export interface GlobalConfig {
  server_url?: string;
  email?: string;
  selected_workspace_id?: string;
  selected_project_id?: string;
  selected_environment?: string;
  workspaces?: Record<string, { name: string; key: string; role: string; type: string }>;
}

export interface TokenFile {
  access_token?: string;
  refresh_token?: string;
  expires_at?: string;
}

export interface ProjectConfig {
  server_url?: string;
  project_id?: string;
  project_name?: string;
  description?: string;
  environment?: string;
  workspace_id?: string;
  workspace_name?: string;
  last_pull?: string;
  last_push?: string;
}

export interface ProxyPid {
  pid: number;
  startedAt: number;
  port: number;
}

export function homeDir(): string {
  return process.env['AGENTSECRETS_HOME'] || os.homedir();
}

export function globalDir(): string {
  return path.join(homeDir(), '.agentsecrets');
}

function readJson<T>(file: string): T | null {
  try {
    const raw = fs.readFileSync(file, 'utf8');
    if (!raw.trim()) return null;
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

function writeJson(file: string, data: unknown, mode: number): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n', { mode });
}

export function loadGlobalConfig(): GlobalConfig | null {
  return readJson<GlobalConfig>(path.join(globalDir(), 'config.json'));
}

export function saveGlobalConfig(cfg: GlobalConfig): void {
  writeJson(path.join(globalDir(), 'config.json'), cfg, 0o600);
}

/** Legacy JWT file. Post-migration this is empty; honored when populated. */
export function loadLegacyTokens(): TokenFile | null {
  return readJson<TokenFile>(path.join(globalDir(), 'token.json'));
}

/** Walk up from cwd to find .agentsecrets/project.json. Mirrors GetProjectRoot. */
export function findProjectRoot(cwd: string): string | null {
  let dir = path.resolve(cwd);
  for (;;) {
    try {
      if (fs.statSync(path.join(dir, '.agentsecrets', 'project.json')).isFile()) return dir;
    } catch {
      /* not here */
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

export function loadProjectConfig(cwd: string): { root: string; config: ProjectConfig } | null {
  const root = findProjectRoot(cwd);
  if (!root) return null;
  const cfg = readJson<ProjectConfig>(path.join(root, '.agentsecrets', 'project.json'));
  if (!cfg) return null;
  return { root, config: cfg };
}

export function saveProjectConfig(cwd: string, cfg: ProjectConfig): void {
  const found = findProjectRoot(cwd);
  const root = found ?? path.resolve(cwd);
  fs.mkdirSync(path.join(root, '.agentsecrets'), { recursive: true, mode: 0o755 });
  fs.writeFileSync(path.join(root, '.agentsecrets', 'project.json'), JSON.stringify(cfg, null, 2) + '\n', {
    mode: 0o644,
  });
}

/** Parse ~/.agentsecrets/proxy.pid ("pid\nstart_unix\nport"). Mirrors ReadPIDFile. */
export function readProxyPid(): ProxyPid | null {
  try {
    const raw = fs.readFileSync(path.join(globalDir(), 'proxy.pid'), 'utf8').trim().split('\n');
    if (raw.length < 3) return null;
    const pid = Number.parseInt(raw[0] ?? '', 10);
    const startedAt = Number.parseInt(raw[1] ?? '', 10);
    const port = Number.parseInt(raw[2] ?? '', 10);
    if (!Number.isFinite(pid) || pid <= 0 || !Number.isFinite(port) || port <= 0) return null;
    return { pid, startedAt, port };
  } catch {
    return null;
  }
}

export interface ServerResolution {
  url: string;
  source: string;
}

/**
 * Resolve the control-plane base URL. Mirrors ResolveServerTarget:
 * AGENTSECRETS_SERVER_URL > AGENTSECRETS_API_URL > project.json >
 * global config > default. A URL is not a credential — safe in MCP config.
 */
export function resolveServer(cwd: string): ServerResolution {
  const envUrl = process.env['AGENTSECRETS_SERVER_URL'] || process.env['AGENTSECRETS_API_URL'];
  if (envUrl) {
    const url = normalizeServerUrl(envUrl);
    return {
      url,
      source: process.env['AGENTSECRETS_SERVER_URL']
        ? 'AGENTSECRETS_SERVER_URL'
        : 'AGENTSECRETS_API_URL',
    };
  }
  const proj = loadProjectConfig(cwd);
  if (proj?.config.server_url) {
    return { url: normalizeServerUrl(proj.config.server_url), source: 'project.json' };
  }
  const g = loadGlobalConfig();
  if (g?.server_url) {
    return { url: normalizeServerUrl(g.server_url), source: 'global config' };
  }
  return { url: DEFAULT_BASE_URL, source: 'default' };
}

export interface EnvResolution {
  name: string;
  source: string;
}

/** Mirrors ResolveEnvironmentWithSource (env > project.json > global > development). */
export function resolveEnvironment(cwd: string): EnvResolution {
  const fromEnv = process.env['AGENTSECRETS_ENV'];
  if (fromEnv) {
    if (isValidEnvironment(fromEnv)) return { name: fromEnv, source: 'AGENTSECRETS_ENV' };
    return { name: 'development', source: 'default (AGENTSECRETS_ENV invalid)' };
  }
  const proj = loadProjectConfig(cwd);
  if (proj?.config.environment && isValidEnvironment(proj.config.environment)) {
    return { name: proj.config.environment, source: 'project.json' };
  }
  const g = loadGlobalConfig();
  if (g?.selected_environment && isValidEnvironment(g.selected_environment)) {
    return { name: g.selected_environment, source: 'global config' };
  }
  return { name: 'development', source: 'default' };
}

export interface ProjectResolution {
  projectId: string;
  projectName: string;
  workspaceId: string;
  workspaceName: string;
  source: 'project.json' | 'global config';
}

/**
 * Resolve the active project. Prefers the directory-bound project.json
 * (like the CLI); falls back to the globally selected project + cached
 * workspace metadata so headless/remote contexts still work.
 */
export function resolveProject(cwd: string): ProjectResolution | null {
  const proj = loadProjectConfig(cwd);
  if (proj?.config.project_id) {
    return {
      projectId: proj.config.project_id,
      projectName: proj.config.project_name ?? '',
      workspaceId: proj.config.workspace_id ?? '',
      workspaceName: proj.config.workspace_name ?? '',
      source: 'project.json',
    };
  }
  const g = loadGlobalConfig();
  const selected = g?.selected_project_id;
  if (g && selected) {
    // Workspace comes from the selected workspace cache.
    const wsId = g.selected_workspace_id ?? '';
    const ws = wsId ? g.workspaces?.[wsId] : undefined;
    return {
      projectId: selected,
      projectName: '',
      workspaceId: wsId,
      workspaceName: ws?.name ?? '',
      source: 'global config',
    };
  }
  return null;
}

/** Resolve the desired proxy port without network I/O (probe happens per call). */
export function resolveProxyPort(): number | null {
  const fromEnv = process.env['AGENTSECRETS_PROXY_PORT'];
  if (fromEnv) {
    const p = Number.parseInt(fromEnv, 10);
    if (Number.isFinite(p) && p > 0 && p < 65536) return p;
  }
  return readProxyPid()?.port ?? null;
}
