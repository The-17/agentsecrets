import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { dispatch } from '../src/tools/common.js';
import { clearPingCache } from '../src/local/binary.js';
import type { CallCtx } from '../src/resolver/index.js';

const SAVED_PATH = process.env['PATH'] ?? '';
const SAVED_BINARY = process.env['AGENTSECRETS_BINARY'];
const SAVED_HOME = process.env['AGENTSECRETS_HOME'];
let binDir = '';
let home = '';

function installEchoFake(): string {
  binDir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-dfake-'));
  const js = `import fs from 'node:fs';
const [, , , , verb, argvJson] = process.argv;
let raw = argvJson ?? '';
if (!raw && !process.stdin.isTTY) { try { raw = fs.readFileSync(0, 'utf8'); } catch { raw = ''; } }
const args = raw ? JSON.parse(raw) : {};
console.log(JSON.stringify({ ok: true, data: { verb, args } }));
`;
  let full: string;
  if (process.platform === 'win32') {
    const script = path.join(binDir, 'agentsecrets.mjs');
    fs.writeFileSync(script, js);
    full = path.join(binDir, 'agentsecrets.cmd');
    fs.writeFileSync(full, `@echo off\r\nnode "${script}" %*\r\n`);
  } else {
    full = path.join(binDir, 'agentsecrets');
    fs.writeFileSync(full, `#!/usr/bin/env node\n${js}`);
    fs.chmodSync(full, 0o755);
  }
  process.env['PATH'] = `${binDir}${path.delimiter}${SAVED_PATH}`;
  delete process.env['AGENTSECRETS_BINARY'];
  return full;
}

function localCall(binary: string, dir: string): CallCtx {
  const creds = {
    token: null, tokenKind: null, tokenSource: null, agentToken: null,
    agentId: null, sessionToken: null, workspaceKey: null, workspaceKeySource: null,
  };
  return {
    mode: { mode: 'local', binary, bridgeVersion: '9.9.9', reason: 'test' },
    creds,
    ctx: {
      creds,
      server: { url: 'https://x', source: 'test' },
      env: { name: 'development', source: 'test' },
      project: null,
      proxyPort: null,
      cwd: dir,
    },
    dir,
    server: { url: 'https://x', source: 'test' },
    resolverBase: 'https://r',
  } as CallCtx;
}

beforeEach(() => {
  clearPingCache();
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'as-dhome-'));
  process.env['AGENTSECRETS_HOME'] = home;
});

afterEach(() => {
  process.env['PATH'] = SAVED_PATH;
  if (SAVED_BINARY === undefined) delete process.env['AGENTSECRETS_BINARY'];
  else process.env['AGENTSECRETS_BINARY'] = SAVED_BINARY;
  if (SAVED_HOME === undefined) delete process.env['AGENTSECRETS_HOME'];
  else process.env['AGENTSECRETS_HOME'] = SAVED_HOME;
  if (binDir) fs.rmSync(binDir, { recursive: true, force: true });
  if (home) fs.rmSync(home, { recursive: true, force: true });
  binDir = '';
  clearPingCache();
});

describe('local dispatch contract (TS -> helper)', () => {
  it('forwards scope as expect_* and echoes context + records telemetry', async () => {
    const bin = installEchoFake();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-ddir-'));
    try {
      const out = await dispatch(localCall(bin, dir), 'echo', { project: 'P1', workspace: 'W1', other: 1 }, async () => {
        throw new Error('cloud path must not run in local mode');
      });
      assert.equal(out.isError, undefined);
      const body = JSON.parse((out.content[0] as { text: string }).text) as Record<string, unknown>;
      // withContext spreads object data alongside the context echo.
      assert.equal(body['verb'], 'echo');
      const fwd = body['args'] as Record<string, unknown>;
      // Requested scope forwarded for the helper's guard; raw names preserved.
      assert.equal(fwd['expect_project'], 'P1');
      assert.equal(fwd['expect_workspace'], 'W1');
      assert.equal(fwd['project'], 'P1');
      // Context echo present.
      assert.ok(body['context']);
      // Telemetry recorded for the tool call.
      const tel = JSON.parse(
        fs.readFileSync(path.join(home, '.agentsecrets', 'telemetry.json'), 'utf8')
      ) as { daily: Record<string, { command_executions: Record<string, number> }> };
      const day = tel.daily[Object.keys(tel.daily)[0] as string] as { command_executions: Record<string, number> };
      assert.equal(day.command_executions['mcp-bridge.echo'], 1);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('transport failure becomes an isError result (no throw)', async () => {
    const out = await dispatch(
      localCall(path.join(os.tmpdir(), 'as-definitely-missing-binary'), os.tmpdir()),
      'echo',
      {},
      async () => { throw new Error('cloud path must not run in local mode'); }
    );
    assert.equal(out.isError, true);
    const text = (out.content[0] as { text: string }).text;
    assert.match(text, /failed to launch/);
  });
});
