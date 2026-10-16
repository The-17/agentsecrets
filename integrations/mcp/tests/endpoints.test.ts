import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeServerUrl,
  resolveEndpoint,
  joinUrl,
  DEFAULT_BASE_URL,
  ENDPOINTS,
} from '../src/resolver/endpoints.js';

describe('normalizeServerUrl (mirrors Go NormalizeServerURL)', () => {
  it('empty -> default control plane', () => {
    assert.equal(normalizeServerUrl(''), DEFAULT_BASE_URL);
    assert.equal(normalizeServerUrl('   '), DEFAULT_BASE_URL);
  });
  it('adds https scheme by default', () => {
    assert.equal(normalizeServerUrl('secrets.company.com'), 'https://secrets.company.com/api');
  });
  it('adds http for localhost/loopback', () => {
    assert.equal(normalizeServerUrl('localhost:8000'), 'http://localhost:8000/api');
    assert.equal(normalizeServerUrl('127.0.0.1:8765'), 'http://127.0.0.1:8765/api');
  });
  it('strips trailing slashes, keeps explicit path', () => {
    assert.equal(normalizeServerUrl('https://x.example.com/api/'), 'https://x.example.com/api');
    assert.equal(normalizeServerUrl('https://x.example.com/custom///'), 'https://x.example.com/custom');
  });
  it('appends /api only when path is empty', () => {
    assert.equal(normalizeServerUrl('https://x.example.com'), 'https://x.example.com/api');
  });
});

describe('resolveEndpoint (mirrors Go endpointMap)', () => {
  it('resolves known endpoints with params', () => {
    assert.equal(
      resolveEndpoint('secrets.delete', { project_id: 'p1', environment: 'production', key: 'K' }),
      'secrets/p1/production/K/'
    );
    assert.equal(resolveEndpoint('projects.list'), 'projects/');
    assert.equal(
      resolveEndpoint('agents.token_issue', { workspace_id: 'w', registration_id: 'areg_1' }),
      'workspaces/w/agents/areg_1/tokens/'
    );
  });
  it('rejects malformed keys', () => {
    assert.throws(() => resolveEndpoint('noseparator'), /must be 'category.action'/);
  });
  it('rejects unknown endpoints (fail fast)', () => {
    assert.throws(() => resolveEndpoint('nope.nope'), /unknown endpoint/);
  });
  it('rejects unfilled placeholders', () => {
    assert.throws(() => resolveEndpoint('secrets.get', { project_id: 'p' }), /unfilled params/);
  });
  it('endpoint map covers every tool backend', () => {
    for (const key of [
      'secrets.list', 'secrets.create', 'secrets.delete',
      'projects.list', 'projects.create', 'projects.get', 'projects.update', 'projects.delete',
      'workspaces.list', 'workspaces.create', 'workspaces.members',
      'agents.list', 'agents.delete', 'agents.token_issue', 'agents.token_list', 'agents.token_revoke',
      'log.list', 'log.detail', 'log.summary',
      'users.public_key',
    ]) {
      assert.ok(resolveEndpoint(key, fillAll(key)), key);
    }
  });
});

function fillAll(key: string): Record<string, string> {
  const path = key.split('.').reduce<Record<string, Record<string, string>>>((m, _, i, a) => m, ENDPOINTS)[key.split('.')[0] as string]?.[key.split('.')[1] as string] ?? '';
  const out: Record<string, string> = {};
  for (const m of path.matchAll(/\{([^}]+)\}/g)) out[m[1] as string] = 'x';
  return out;
}

describe('joinUrl', () => {
  it('joins without double slashes', () => {
    assert.equal(joinUrl('https://h/api/', '/v1/resolve'), 'https://h/api/v1/resolve');
    assert.equal(joinUrl('https://h/api', 'v1/resolve'), 'https://h/api/v1/resolve');
  });
});
