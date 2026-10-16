import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { resolveCredentials, decodeWorkspaceKey, isJwtShape } from '../src/auth/chain.js';

// JWT-shaped fixture (shape only — signature is fake). Classification keys
// off shape (3 dot-segments + eyJ header), never content.
const JWT_FIXTURE = 'eyJhYmMiOiJkZWYifQ.eyJhYmMiOiJkZWYifQ.c2ln';
// Raw workload secret as issued (token_urlsafe(32) → 43 chars, no dots).
const RAW_FIXTURE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm1234';

const SAVED = { ...process.env };
let home = '';

function setHome(): void {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'as-chain-'));
  process.env['AGENTSECRETS_HOME'] = home;
}

beforeEach(() => {
  for (const k of Object.keys(process.env)) {
    if (k.startsWith('AGENTSECRETS_') || k === 'AS_AGENT_TOKEN' || k === 'AWS_WEB_IDENTITY_TOKEN_FILE') {
      delete process.env[k];
    }
  }
  delete process.env['AGENTSECRETS_HOME'];
  setHome();
});

afterEach(() => {
  process.env = { ...SAVED };
  if (home) fs.rmSync(home, { recursive: true, force: true });
});

function writeFile(rel: string, content: string, mode = 0o600): string {
  const file = path.join(home, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, { mode });
  return file;
}

describe('token chain', () => {
  it('empty env, no files -> nulls', async () => {
    const c = await resolveCredentials();
    assert.equal(c.token, null);
    assert.equal(c.agentToken, null);
    assert.equal(c.workspaceKey, null);
  });
  it('AGENTSECRETS_TOKEN JWT wins', async () => {
    process.env['AGENTSECRETS_TOKEN'] = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig';
    const c = await resolveCredentials();
    assert.equal(c.tokenKind, 'jwt');
    assert.equal(c.tokenSource, 'AGENTSECRETS_TOKEN');
  });
  it('agt_ token classifies as workload identity', async () => {
    process.env['AGENTSECRETS_TOKEN'] = 'agt_ws_abc123';
    const c = await resolveCredentials();
    assert.equal(c.token, null);
    assert.equal(c.agentToken, 'agt_ws_abc123');
  });
  it('files are last resort: session beats file, legacy beats file', async () => {
    const f = writeFile('tok', JWT_FIXTURE);
    process.env['AGENTSECRETS_TOKEN_FILE'] = f;
    let c = await resolveCredentials();
    assert.equal(c.token, JWT_FIXTURE);
    assert.equal(c.tokenSource, 'AGENTSECRETS_TOKEN_FILE');
    writeFile('.agentsecrets/token.json', JSON.stringify({ access_token: JWT_FIXTURE }));
    c = await resolveCredentials();
    assert.equal(c.token, JWT_FIXTURE);
    assert.equal(c.tokenSource, '~/.agentsecrets/token.json');
    writeFile(
      '.agentsecrets/mcp-session.json',
      JSON.stringify({ oauth: { access_token: 'oauth-jwt', refresh_token: null, expires_at: null, token_url: 'u', client_id: 'c' }, identities: {}, defaults: { workspace_id: null, project_id: null, project_name: null } })
    );
    c = await resolveCredentials();
    assert.equal(c.token, 'oauth-jwt');
    assert.equal(c.tokenSource, 'OAuth session (auth_login)');
  });
  it('file agt_ still feeds workload lookup when JWT comes from elsewhere', async () => {
    const f = writeFile('tok', 'agt_from_file');
    process.env['AGENTSECRETS_TOKEN_FILE'] = f;
    writeFile('.agentsecrets/token.json', JSON.stringify({ access_token: JWT_FIXTURE }));
    const c = await resolveCredentials();
    assert.equal(c.token, JWT_FIXTURE);
    assert.equal(c.agentToken, 'agt_from_file');
  });
  it('raw token_urlsafe secret classifies as workload, never management JWT', async () => {
    // Regression: issued token VALUES are 43-char opaque strings, not agt_
    // IDs. They must resolve as agent identity, or cloud resolve breaks.
    assert.equal(RAW_FIXTURE.length, 43);
    process.env['AGENTSECRETS_TOKEN'] = RAW_FIXTURE;
    const c = await resolveCredentials();
    assert.equal(c.token, null);
    assert.equal(c.tokenKind, null);
    assert.equal(c.agentToken, RAW_FIXTURE);
  });
  it('isJwtShape separates JWTs from workload credentials', () => {
    // Rule (lockstep with resolver isWorkloadToken): dot-bearing = login
    // posture, dot-free = workload credential.
    assert.equal(isJwtShape('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig'), true);
    assert.equal(isJwtShape('h.eyJhYmMiOiJkZWYifQ.s'), true);
    assert.equal(isJwtShape('a.b.c'), true);
    assert.equal(isJwtShape('a..c'), true);
    assert.equal(isJwtShape(RAW_FIXTURE), false);
    assert.equal(isJwtShape('agt_ws_abc123'), false);
    assert.equal(isJwtShape('Bearer agt_x'), false);
    assert.equal(isJwtShape(''), false);
  });
  it('agent token slots (env + file)', async () => {
    process.env['AS_AGENT_TOKEN'] = 'agt_a';
    let c = await resolveCredentials();
    assert.equal(c.agentToken, 'agt_a');
    delete process.env['AS_AGENT_TOKEN'];
    const f = writeFile('agt', 'agt_b');
    process.env['AGENTSECRETS_AGENT_TOKEN_FILE'] = f;
    c = await resolveCredentials();
    assert.equal(c.agentToken, 'agt_b');
  });
  it('pinned session identity fills agentToken per workspace', async () => {
    writeFile(
      '.agentsecrets/mcp-session.json',
      JSON.stringify({ oauth: null, identities: { ws1: { registration_id: 'areg_1', agent_name: 'a', token: 'agt_pinned', label: 'mcp-bridge', pinned_at: '', workspace_id: 'ws1', project_id: null, environment: null, scope_source: 'registration' } }, defaults: { workspace_id: null, project_id: null, project_name: null } })
    );
    const c = await resolveCredentials({ workspaceId: 'ws1' });
    assert.equal(c.agentToken, 'agt_pinned');
    const other = await resolveCredentials({ workspaceId: 'ws2' });
    assert.equal(other.agentToken, null);
  });
  it('pinned raw secret (not agt_ id) resolves as the workspace identity', async () => {
    // Live shape: agent_token_issue stores the raw issued secret; the agt_
    // string is only the public identifier. The pin must work either way.
    writeFile(
      '.agentsecrets/mcp-session.json',
      JSON.stringify({ oauth: null, identities: { ws1: { registration_id: 'areg_1', agent_name: 'a', token: RAW_FIXTURE, label: 'mcp-bridge', pinned_at: '', workspace_id: 'ws1', project_id: null, environment: null, scope_source: 'registration' } }, defaults: { workspace_id: null, project_id: null, project_name: null } })
    );
    const c = await resolveCredentials({ workspaceId: 'ws1' });
    assert.equal(c.agentToken, RAW_FIXTURE);
  });
  it('declared + session identities', async () => {
    process.env['AGENTSECRETS_AGENT_ID'] = 'ci-agent';
    process.env['AGENTSECRETS_SESSION_TOKEN'] = 'as_sess_x';
    const c = await resolveCredentials();
    assert.equal(c.agentId, 'ci-agent');
    assert.equal(c.sessionToken, 'as_sess_x');
  });
});

describe('decodeWorkspaceKey (Go GetWorkspaceKey tolerance)', () => {
  it('raw 32 bytes', () => {
    const raw = Buffer.alloc(32, 7).toString('base64');
    assert.deepEqual(decodeWorkspaceKey(raw), Buffer.alloc(32, 7));
  });
  it('double-encoded 44-char form', () => {
    const inner = Buffer.alloc(32, 9).toString('base64');
    assert.equal(inner.length, 44);
    const outer = Buffer.from(inner, 'utf8').toString('base64');
    assert.deepEqual(decodeWorkspaceKey(outer), Buffer.alloc(32, 9));
  });
  it('rejects garbage', () => {
    assert.equal(decodeWorkspaceKey('!!!'), null);
    assert.equal(decodeWorkspaceKey(Buffer.alloc(16).toString('base64')), null);
    assert.equal(decodeWorkspaceKey(''), null);
  });
});
