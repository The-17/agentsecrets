import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * End-to-end wire test: spawn the BUILT bridge (dist/index.js) and speak
 * MCP JSON-RPC over stdio. Runs fully isolated: scrubbed env, temp HOME,
 * forced cloud mode — no local state, binary, or network required
 * (auth_status/tools/list touch nothing external).
 */
const here = path.dirname(fileURLToPath(import.meta.url));
const distIndex = path.join(here, '..', '..', 'dist', 'index.js');
// Expected server version tracks package.json (single source of truth).
const expectedVersion = (JSON.parse(fs.readFileSync(path.join(here, '..', '..', 'package.json'), 'utf8')) as { version: string }).version;

let child: ChildProcess;
let lines: string[] = [];
let buf = '';
let nextId = 1;
const pending = new Map<number, (msg: Record<string, unknown>) => void>();

function send(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`no response for ${method} within 15s`));
    }, 15000);
    pending.set(id, (msg) => {
      clearTimeout(timer);
      resolve(msg);
    });
    child.stdin?.write(JSON.stringify({ jsonrpc: '2.0', id, method, params: params ?? {} }) + '\n');
  });
}

function notify(method: string): void {
  child.stdin?.write(JSON.stringify({ jsonrpc: '2.0', method }) + '\n');
}

before(async () => {
  assert.ok(fs.existsSync(distIndex), `build first: ${distIndex} missing`);
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'as-wire-home-'));
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined && !k.startsWith('AGENTSECRETS_') && k !== 'AS_AGENT_TOKEN' && k !== 'AWS_WEB_IDENTITY_TOKEN_FILE') {
      env[k] = v;
    }
  }
  env['AGENTSECRETS_HOME'] = home;
  env['AGENTSECRETS_MCP_MODE'] = 'cloud';
  (globalThis as unknown as { __wireHome: string }).__wireHome = home;
  child = spawn(process.execPath, [distIndex], { env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  // Windows pipes can drop bytes written in the first instants after spawn;
  // wait for the process to be alive before the handshake.
  await new Promise<void>((resolve, reject) => {
    child.once('spawn', () => resolve());
    child.once('error', (e) => reject(e));
  });
  await new Promise((r) => setTimeout(r, 500));
  child.stdout?.on('data', (chunk: Buffer) => {
    buf += chunk.toString('utf8');
    let idx: number;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (!line) continue;
      lines.push(line);
      try {
        const msg = JSON.parse(line) as Record<string, unknown>;
        if (typeof msg['id'] === 'number' && pending.has(msg['id'])) {
          pending.get(msg['id'])?.(msg);
          pending.delete(msg['id'] as number);
        }
      } catch {
        /* ignore malformed */
      }
    }
  });
  let stderr = '';
  child.stderr?.on('data', (c: Buffer) => {
    stderr += c.toString('utf8');
  });
  (globalThis as unknown as { __wireStderr: () => string }).__wireStderr = () => stderr;
});

after(() => {
  child.kill();
  const home = (globalThis as unknown as { __wireHome: string }).__wireHome;
  if (home) fs.rmSync(home, { recursive: true, force: true });
});

describe('MCP stdio wire protocol', () => {
  it('handshakes (initialize)', async () => {
    // Warm the Windows pipe: the first bytes after spawn are occasionally
    // lost under parallel load. `ping` is idempotent and pre-init safe
    // (any answer — result or error — proves the round trip).
    let warmed = false;
    for (let attempt = 1; attempt <= 3 && !warmed; attempt++) {
      try {
        await send('ping');
        warmed = true;
      } catch {
        if (attempt === 3) throw new Error('stdio pipe never became responsive (3 ping attempts)');
      }
    }
    const res = await send('initialize', {
      protocolVersion: '2025-03-26',
      capabilities: {},
      clientInfo: { name: 'wire-test', version: '1.0.0' },
    });
    assert.ok(!res['error'], `initialize error: ${JSON.stringify(res['error'])}`);
    const result = res['result'] as Record<string, unknown>;
    const serverInfo = result['serverInfo'] as Record<string, unknown>;
    assert.equal(serverInfo['name'], 'agentsecrets-mcp');
    assert.equal(serverInfo['version'], expectedVersion);
    notify('notifications/initialized');
  });

  it('lists all 30 tools with schemas', async () => {
    const res = await send('tools/list');
    const result = res['result'] as { tools: Array<{ name: string; inputSchema?: unknown }> };
    assert.equal(result.tools.length, 30);
    const names = result.tools.map((t) => t.name);
    for (const want of ['proxy_call', 'secrets_list', 'project_use', 'workspace_switch', 'agent_token_issue', 'logs_detail', 'auth_status', 'auth_use_identity']) {
      assert.ok(names.includes(want), want);
    }
    const proxyCall = result.tools.find((t) => t.name === 'proxy_call');
    const schema = proxyCall?.inputSchema as Record<string, unknown>;
    assert.ok(schema && typeof schema === 'object' && 'injections' in (schema['properties'] as object));
  });

  it('auth_status works with zero configuration', async () => {
    const res = await send('tools/call', { name: 'auth_status', arguments: {} });
    assert.ok(!res['error'], `tools/call error: ${JSON.stringify(res['error'])}`);
    const result = res['result'] as { content: Array<{ type: string; text: string }>; isError?: boolean };
    assert.equal(result.isError, undefined);
    const body = JSON.parse(result.content[0]?.text ?? '{}') as Record<string, unknown>;
    assert.equal(body['mode'], 'cloud');
    assert.ok(typeof body['next'] === 'string' && (body['next'] as string).includes('auth_login'));
  });

  it('unknown tool surfaces a protocol error (not a crash)', async () => {
    const res = await send('tools/call', { name: 'nope_nope', arguments: {} });
    assert.ok(res['error'], 'expected a JSON-RPC error for unknown tools');
  });
});
