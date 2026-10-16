import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadSession, saveSession, findPinForToken, sessionPath } from '../src/auth/session.js';
import { emptySession } from '../src/resolver/types.js';

const SAVED = { ...process.env };
let home = '';

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'as-sess-'));
  process.env['AGENTSECRETS_HOME'] = home;
});

afterEach(() => {
  process.env = { ...SAVED };
  fs.rmSync(home, { recursive: true, force: true });
});

describe('session store', () => {
  it('missing file -> empty session', () => {
    assert.deepEqual(loadSession(), emptySession());
  });
  it('round-trips identities + defaults + oauth', () => {
    const s = emptySession();
    s.oauth = { access_token: 'a', refresh_token: 'r', expires_at: null, token_url: 'u', client_id: 'c' };
    s.identities['w1'] = {
      registration_id: 'areg_1', agent_name: 'ci', token: 'agt_x', label: 'mcp-bridge',
      pinned_at: 't', workspace_id: 'w1', project_id: 'p1', environment: 'production', scope_source: 'registration',
    };
    s.defaults = { workspace_id: 'w1', project_id: 'p1', project_name: 'P' };
    saveSession(s);
    assert.deepEqual(loadSession(), s);
  });
  it('is 0600 on POSIX', () => {
    if (process.platform === 'win32') return;
    saveSession(emptySession());
    assert.equal(fs.statSync(sessionPath()).mode & 0o777, 0o600);
  });
  it('corrupt file -> empty session (fail safe)', () => {
    fs.mkdirSync(path.dirname(sessionPath()), { recursive: true });
    fs.writeFileSync(sessionPath(), '{nope');
    assert.deepEqual(loadSession(), emptySession());
  });
  it('findPinForToken locates pins', () => {
    const s = emptySession();
    s.identities['w1'] = {
      registration_id: 'areg_1', agent_name: 'ci', token: 'agt_x', label: 'l',
      pinned_at: 't', workspace_id: 'w1', project_id: null, environment: null, scope_source: 'registration',
    };
    saveSession(s);
    const hit = findPinForToken('agt_x');
    assert.equal(hit?.workspaceId, 'w1');
    assert.equal(hit?.pin.agent_name, 'ci');
    assert.equal(findPinForToken('agt_nope'), null);
  });
});
