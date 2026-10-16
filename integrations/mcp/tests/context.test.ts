import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { resolveContext, NoContextError } from '../src/context.js';

const SAVED = { ...process.env };
let home = '';
let projDir = '';

function writeJson(file: string, obj: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(obj));
}

beforeEach(() => {
  for (const k of Object.keys(process.env)) {
    if (k.startsWith('AGENTSECRETS_')) delete process.env[k];
  }
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'as-ctx-home-'));
  process.env['AGENTSECRETS_HOME'] = home;
  projDir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-ctx-proj-'));
  writeJson(path.join(projDir, '.agentsecrets', 'project.json'), {
    project_id: 'p1', project_name: 'P1', environment: 'staging',
    workspace_id: 'w1', workspace_name: 'W1',
  });
});

afterEach(() => {
  process.env = { ...SAVED };
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(projDir, { recursive: true, force: true });
});

const cloudGetNone = null;

describe('resolveContext', () => {
  it('empty world -> NoContextError', async () => {
    await assert.rejects(
      resolveContext({}, { cwd: os.tmpdir(), mode: 'cloud', cloudGet: cloudGetNone }),
      (e: unknown) => e instanceof NoContextError
    );
  });
  it('cwd walk-up finds project.json', async () => {
    const sub = path.join(projDir, 'a', 'b');
    fs.mkdirSync(sub, { recursive: true });
    const out = await resolveContext({}, { cwd: sub, mode: 'local', cloudGet: null });
    assert.equal(out.ctx.projectId, 'p1');
    assert.equal(out.ctx.environment, 'staging');
    assert.equal(out.ctx.source, 'cwd');
    assert.equal(out.dir, projDir);
  });
  it('explicit path wins', async () => {
    const out = await resolveContext({ path: projDir }, { cwd: os.tmpdir(), mode: 'cloud', cloudGet: null });
    assert.equal(out.ctx.source, 'path');
    assert.equal(out.ctx.workspaceId, 'w1');
  });
  it('missing path -> NoContextError', async () => {
    await assert.rejects(
      resolveContext({ path: path.join(os.tmpdir(), 'as-ctx-missing') }, { cwd: os.tmpdir(), mode: 'cloud', cloudGet: null }),
      NoContextError
    );
  });
  it('local mode echoes the binding; enforcement lives in the helper', async () => {
    writeJson(path.join(home, '.agentsecrets', 'config.json'), {
      workspaces: { w1: { name: 'W1', key: '', role: 'owner', type: 'shared' }, w2: { name: 'W2', key: '', role: 'owner', type: 'shared' } },
    });
    // No mismatch error here anymore: the TS path is a thin pipe, and the
    // CLI helper enforces expect_* against its binding (single point).
    const out = await resolveContext({ workspace: 'W2' }, { cwd: projDir, mode: 'local', cloudGet: null });
    assert.equal(out.ctx.projectId, 'p1');
    assert.equal(out.ctx.source, 'cwd');
    assert.equal(out.dir, projDir);
  });
  it('pinned defaults apply', async () => {
    writeJson(path.join(home, '.agentsecrets', 'mcp-session.json'), {
      oauth: null, identities: {},
      defaults: { workspace_id: 'w9', project_id: 'p9', project_name: 'P9' },
    });
    const out = await resolveContext({}, { cwd: os.tmpdir(), mode: 'cloud', cloudGet: null });
    assert.equal(out.ctx.source, 'pinned');
    assert.equal(out.ctx.projectId, 'p9');
  });
  it('env hints route through explicit lookup', async () => {
    process.env['AGENTSECRETS_PROJECT'] = 'P1';
    // cloud without JWT cannot look up names -> guided error (not silent nulls).
    await assert.rejects(
      resolveContext({}, { cwd: os.tmpdir(), mode: 'cloud', cloudGet: null }),
      NoContextError
    );
  });
  it('explicit cloud names need cloudGet (JWT)', async () => {
    await assert.rejects(
      resolveContext({ project: 'P', workspace: 'W' }, { cwd: os.tmpdir(), mode: 'cloud', cloudGet: null }),
      (e: unknown) => e instanceof NoContextError && /needs a control-plane login/.test((e as Error).message)
    );
  });
  it('cloud explicit lookup maps names to IDs', async () => {
    const cloudGet = async (key: string, params?: Record<string, string>): Promise<unknown> => {
      if (key === 'workspaces.list') return [{ id: 'w1', name: 'W1' }];
      if (key === 'projects.get') {
        assert.equal(params?.['workspace_id'], 'w1');
        assert.equal(params?.['project_name'], 'P1');
        return { id: 'p1', name: 'P1' };
      }
      throw new Error(`unexpected ${key}`);
    };
    const out = await resolveContext({ project: 'P1', workspace: 'W1' }, { cwd: os.tmpdir(), mode: 'cloud', cloudGet });
    assert.equal(out.ctx.projectId, 'p1');
    assert.equal(out.ctx.source, 'explicit');
  });
  it('environment override validated', async () => {
    const out = await resolveContext({ path: projDir, environment: 'production' }, { cwd: os.tmpdir(), mode: 'cloud', cloudGet: null });
    assert.equal(out.ctx.environment, 'production');
    await assert.rejects(
      resolveContext({ path: projDir, environment: 'nope' }, { cwd: os.tmpdir(), mode: 'cloud', cloudGet: null }),
      /invalid environment/
    );
  });
});
