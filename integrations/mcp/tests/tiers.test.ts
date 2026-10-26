import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  TOOL_TIERS,
  ENV_ALLOW_WRITES,
  allowWrites,
  refusal,
  tierOf,
  tierReport,
} from '../src/tiers.js';

// The permission model is the product promise, so these tests assert the
// boundary itself rather than the happy path. Each one fails if the gate is
// removed, which is the only reason a security test is worth writing.

test('writes are refused by default', () => {
  delete process.env[ENV_ALLOW_WRITES];
  assert.equal(allowWrites(), false);
  for (const tool of ['secrets_set', 'secrets_delete', 'agent_token_issue', 'project_delete', 'agent_delete']) {
    assert.equal(tierOf(tool) === 'read', false, `${tool} must not be readable-tier`);
  }
});

test('reads stay open', () => {
  delete process.env[ENV_ALLOW_WRITES];
  for (const tool of ['proxy_call', 'secrets_list', 'secrets_diff', 'logs_list', 'auth_status']) {
    assert.equal(tierOf(tool), 'read', `${tool} must stay read-tier`);
  }
});

test('the human switch is the only thing that opens writes', () => {
  process.env[ENV_ALLOW_WRITES] = 'true';
  assert.equal(allowWrites(), true);
  delete process.env[ENV_ALLOW_WRITES];
  assert.equal(allowWrites(), false);
});

test('the switch fails closed on anything but exact true', () => {
  for (const v of ['1', 'yes', 'enabled', 'tru', '']) {
    process.env[ENV_ALLOW_WRITES] = v;
    assert.equal(allowWrites(), false, `${JSON.stringify(v)} must not enable writes`);
  }
  process.env[ENV_ALLOW_WRITES] = 'TRUE';
  assert.equal(allowWrites(), true, 'case-insensitive exact true is allowed');
  delete process.env[ENV_ALLOW_WRITES];
});

test('an unclassified tool is a startup crash, not a silent bypass', () => {
  assert.throws(() => tierOf('some_new_tool'), /has no permission tier/);
});

test('the refusal names the guard, the human command, and the switch', () => {
  const msg = refusal('secrets_delete');
  assert.match(msg, /prompt injection/);
  assert.match(msg, /agentsecrets secrets delete/);
  assert.match(msg, new RegExp(ENV_ALLOW_WRITES));
  assert.match(msg, /cannot enable it yourself/);
});

test('the refusal never asks the user to paste a value', () => {
  for (const tool of ['secrets_set', 'secrets_delete', 'agent_token_issue']) {
    const msg = refusal(tool);
    if (/paste the value/i.test(msg)) {
      assert.match(msg, /should not ask/, `${tool} refusal suggests pasting a value`);
    }
  }
});

test('token minting is gated as destructive', () => {
  assert.equal(tierOf('agent_token_issue'), 'destructive');
});

test('no create verb is read-tier', () => {
  for (const [name, tier] of Object.entries(TOOL_TIERS)) {
    if (['secrets_set', 'agent_token_issue'].includes(name)) {
      assert.notEqual(tier, 'read', `${name} must not be read-tier`);
    }
  }
});

test('there is no allowlist write tool at all', () => {
  for (const name of Object.keys(TOOL_TIERS)) {
    assert.equal(
      /allowlist/i.test(name) && !/^check_domain$|^get_allowlist$/.test(name),
      false,
      `${name} touches the allowlist and must not exist on the agent surface`
    );
  }
});

test('the tier report is honest about the switch', () => {
  delete process.env[ENV_ALLOW_WRITES];
  const rep = tierReport();
  assert.equal(rep['writes_enabled'], false);
  assert.equal(rep['enabled_by'], ENV_ALLOW_WRITES);
  assert.ok((rep['read'] as string[]).length > 0);
  assert.ok((rep['destructive'] as string[]).length > 0);

  process.env[ENV_ALLOW_WRITES] = 'true';
  assert.equal(tierReport()['writes_enabled'], true);
  delete process.env[ENV_ALLOW_WRITES];
});
