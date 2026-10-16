import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { findBinary, pingBinary, clearPingCache, bridgeExec, BridgeError } from '../src/local/binary.js';

const SAVED_PATH = process.env['PATH'] ?? '';
const SAVED_BINARY = process.env['AGENTSECRETS_BINARY'];
let binDir = '';

/** Cross-platform fake `agentsecrets`: a node script (+ .cmd shim on Windows). */
function installFake(): string {
  binDir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-fakebin-'));
  const js = `import fs from 'node:fs';
const [, , , , verb, argvJson] = process.argv;
let raw = argvJson ?? '';
if (!raw && !process.stdin.isTTY) {
  try { raw = fs.readFileSync(0, 'utf8'); } catch { raw = ''; }
}
const args = raw ? JSON.parse(raw) : {};
if (verb === 'ping') {
  console.log(JSON.stringify({ ok: true, data: { version: '9.9.9-test', protocol: 'mcp-bridge-v1', verbs: ['ping', 'echo'], keychain: false } }));
} else if (verb === 'echo') {
  console.log(JSON.stringify({ ok: true, data: { verb, args } }));
} else if (verb === 'fails') {
  console.log(JSON.stringify({ ok: false, error: 'boom-handled' }));
} else if (verb === 'garbage') {
  console.log('not json at all');
} else {
  console.error('unknown verb');
  process.exit(3);
}
`;
  let name: string;
  if (process.platform === 'win32') {
    const script = path.join(binDir, 'agentsecrets.mjs');
    fs.writeFileSync(script, js);
    name = 'agentsecrets.cmd';
    fs.writeFileSync(path.join(binDir, name), `@echo off\r\nnode "${script}" %*\r\n`);
  } else {
    name = 'agentsecrets';
    fs.writeFileSync(path.join(binDir, name), `#!/usr/bin/env node\n${js}`);
    fs.chmodSync(path.join(binDir, name), 0o755);
  }
  process.env['PATH'] = `${binDir}${path.delimiter}${SAVED_PATH}`;
  delete process.env['AGENTSECRETS_BINARY'];
  return path.join(binDir, name);
}

beforeEach(() => {
  clearPingCache();
});

afterEach(() => {
  process.env['PATH'] = SAVED_PATH;
  if (SAVED_BINARY === undefined) delete process.env['AGENTSECRETS_BINARY'];
  else process.env['AGENTSECRETS_BINARY'] = SAVED_BINARY;
  if (binDir) fs.rmSync(binDir, { recursive: true, force: true });
  binDir = '';
  clearPingCache();
});

describe('binary discovery + envelope protocol', () => {
  it('finds the fake on PATH', () => {
    const full = installFake();
    assert.equal(findBinary(), full);
  });
  it('AGENTSECRETS_BINARY override wins', () => {
    const full = installFake();
    process.env['AGENTSECRETS_BINARY'] = full;
    assert.equal(findBinary(), full);
    process.env['AGENTSECRETS_BINARY'] = path.join(binDir, 'missing');
    assert.equal(findBinary(), null);
  });
  it('ping parses capability handshake', () => {
    installFake();
    const info = pingBinary();
    assert.ok(info);
    assert.equal(info?.version, '9.9.9-test');
    assert.deepEqual(info?.verbs, ['ping', 'echo']);
  });
  it('exec unwraps data envelopes', () => {
    const bin = installFake();
    const env = bridgeExec(bin, 'echo', { a: 1 });
    assert.equal(env.ok, true);
    assert.deepEqual(env.data, { verb: 'echo', args: { a: 1 } });
  });
  it('exec surfaces ok:false as BridgeError (exit stays 0)', () => {
    const bin = installFake();
    assert.throws(() => bridgeExec(bin, 'fails', {}), (e: unknown) => e instanceof BridgeError && /boom-handled/.test(e.message));
  });
  it('exec rejects non-JSON stdout', () => {
    const bin = installFake();
    assert.throws(() => bridgeExec(bin, 'garbage', {}), BridgeError);
  });
  it('exec reports nonzero exits with stderr tail', () => {
    const bin = installFake();
    assert.throws(() => bridgeExec(bin, 'nope', {}), (e: unknown) => e instanceof BridgeError && /exited 3/.test(e.message));
  });
});
