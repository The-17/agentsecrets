import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { recordTool, recordError, recordSecretCount } from '../src/telemetry.js';

const SAVED = { ...process.env };
let home = '';

function telemetryFile(): string {
  return path.join(home, '.agentsecrets', 'telemetry.json');
}

function read(): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(telemetryFile(), 'utf8')) as Record<string, unknown>;
}

beforeEach(() => {
  for (const k of Object.keys(process.env)) {
    if (k.startsWith('AGENTSECRETS_')) delete process.env[k];
  }
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'as-tel-'));
  process.env['AGENTSECRETS_HOME'] = home;
});

afterEach(() => {
  process.env = { ...SAVED };
  fs.rmSync(home, { recursive: true, force: true });
});

describe('bridge telemetry (same file/shape the CLI syncs)', () => {
  it('records per-tool counts + integration marker', () => {
    recordTool('proxy_call');
    recordTool('proxy_call');
    recordTool('auth_status');
    const data = read();
    const daily = data['daily'] as Record<string, Record<string, unknown>>;
    const day = daily[Object.keys(daily)[0] as string] as Record<string, unknown>;
    assert.deepEqual(day['command_executions'], { 'mcp-bridge.proxy_call': 2, 'mcp-bridge.auth_status': 1 });
    assert.equal(day['developer_commands'], 3);
    assert.deepEqual(day['integrations_active'], ['mcp-bridge']);
    assert.match(String(day['cli_version']), /^mcp-bridge\//);
    assert.ok(typeof day['os'] === 'string' && typeof day['arch'] === 'string');
  });
  it('records error categories', () => {
    recordError('auth');
    recordError('network');
    recordError('secrets');
    recordError('unknown');
    const data = read();
    const day = (data['daily'] as Record<string, Record<string, unknown>>)[Object.keys(data['daily'] as object)[0] as string] as Record<string, unknown>;
    assert.equal(day['errors_auth_count'], 1);
    assert.equal(day['errors_network_count'], 1);
    assert.equal(day['errors_secrets_count'], 1);
    assert.equal(day['errors_unknown_count'], 1);
  });
  it('records secret counts', () => {
    recordSecretCount(12);
    const data = read();
    const day = (data['daily'] as Record<string, Record<string, unknown>>)[Object.keys(data['daily'] as object)[0] as string] as Record<string, unknown>;
    assert.equal(day['project_secret_count'], 12);
  });
  it('preserves fields written by the Go side', () => {
    const today = new Date().toISOString().slice(0, 10);
    const seed = {
      last_sync: '2026-01-01T00:00:00Z',
      daily: {
        [today]: {
          command_executions: { root: 3 },
          workspace_member_count: 5,
          user_email: 'a@b.c',
          project_secret_count: 9,
        },
      },
    };
    fs.mkdirSync(path.dirname(telemetryFile()), { recursive: true });
    fs.writeFileSync(telemetryFile(), JSON.stringify(seed));
    recordTool('x');
    const data = read();
    const day = (data['daily'] as Record<string, Record<string, unknown>>)[today] as Record<string, unknown>;
    // Untouched passthrough (Go drops unknown fields on ITS writes; we must not).
    assert.equal(day['workspace_member_count'], 5);
    assert.equal(day['user_email'], 'a@b.c');
    const execs = day['command_executions'] as Record<string, number>;
    assert.equal(execs['root'], 3);
    assert.equal(execs['mcp-bridge.x'], 1);
  });
  it('corrupt file does not throw (fail-open)', () => {
    fs.mkdirSync(path.dirname(telemetryFile()), { recursive: true });
    fs.writeFileSync(telemetryFile(), '{broken');
    recordTool('x');
    recordError('auth');
    const data = read();
    assert.ok(data['daily']);
  });
  it('file is 0600 on POSIX', () => {
    if (process.platform === 'win32') return;
    recordTool('x');
    assert.equal(fs.statSync(telemetryFile()).mode & 0o777, 0o600);
  });
});
