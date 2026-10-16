import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createBridgeServer, BRIDGE_VERSION, TOOL_NAMES, TOOL_DESCRIPTIONS, SERVER_INSTRUCTIONS } from '../src/server.js';
import { sanitize } from '../src/tools/common.js';

// Tests run compiled from dist-tests/tests/ -> package root is two levels up.
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

describe('server wiring', () => {
  it('registers the full 27-tool surface without throwing', () => {
    const server = createBridgeServer();
    assert.ok(server);
    assert.equal(TOOL_NAMES.length, 27);
    assert.equal(new Set(TOOL_NAMES).size, 27);
    for (const group of ['proxy_', 'secrets_', 'project_', 'workspace_', 'agent_', 'logs_', 'auth_']) {
      assert.ok(TOOL_NAMES.some((n) => n.startsWith(group)), group);
    }
  });
  it('bridge version matches package.json', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')) as { version: string };
    assert.equal(BRIDGE_VERSION, pkg.version);
  });
});

describe('agent-facing documentation (naive-agent proof)', () => {
  it('server instructions orient a first-time agent', () => {
    for (const must of [
      'KEY NAMES',
      'auth_status',
      'never',
      'confirm',
    ]) {
      assert.ok(SERVER_INSTRUCTIONS.includes(must), must);
    }
    assert.ok(SERVER_INSTRUCTIONS.length > 500);
  });
  it('every registered tool has a substantive self-contained description', () => {
    assert.deepEqual(Object.keys(TOOL_DESCRIPTIONS).sort(), [...TOOL_NAMES].sort());
    for (const name of TOOL_NAMES) {
      const d = TOOL_DESCRIPTIONS[name] as string;
      assert.ok(d && d.length >= 80, `${name}: too short to guide a naive agent`);
      // No unexplained insider shorthand; no placeholder text.
      assert.ok(!/TODO|FIXME|XXX/i.test(d), `${name}: contains placeholder`);
    }
  });
  it('destructive tools demand human approval in their own text', () => {
    for (const name of ['secrets_delete', 'project_delete', 'agent_delete']) {
      const d = TOOL_DESCRIPTIONS[name] as string;
      assert.ok(d.includes('confirm:true') || d.includes('confirm'), `${name}: missing confirm`);
      assert.ok(/human/i.test(d), `${name}: missing human-approval rule`);
    }
  });
  it('credentialed-call tool states the key-name rule with an example', () => {
    const d = TOOL_DESCRIPTIONS['proxy_call'] as string;
    assert.ok(/STRIPE_KEY/.test(d));
    assert.ok(/never/i.test(d));
  });
});

describe('sanitize (error-text redaction)', () => {
  it('redacts token-shaped strings', () => {
    const out = sanitize('failed for agt_ws_abc123 and eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln and as_sess_deadbeef');
    assert.ok(!out.includes('agt_ws_abc123'));
    assert.ok(!out.includes('eyJhbGciOiJIUzI1NiJ9'));
    assert.ok(!out.includes('as_sess_deadbeef'));
    assert.match(out, /\[REDACTED\]/);
  });
  it('leaves ordinary messages alone', () => {
    assert.equal(sanitize('workspace "W1" not found'), 'workspace "W1" not found');
  });
});
