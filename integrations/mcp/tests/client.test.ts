import { strict as assert } from 'node:assert';
import { test, beforeEach, afterEach } from 'node:test';
import { cloudResolve, controlCall, ApiError, MAX_RESPONSE_BYTES } from '../src/resolver/client.js';

const HUGE = 'A'.repeat(MAX_RESPONSE_BYTES + 1024);

function installFetch(handler: (url: string, init: any) => Response) {
  const prev = globalThis.fetch;
  globalThis.fetch = (async (url: any, init: any) => handler(String(url), init)) as any;
  return () => {
    globalThis.fetch = prev;
  };
}

beforeEach(() => {});
afterEach(() => {
  // ensure fetch is restored between tests
  // (each test installs its own; harmless if already restored)
});

test('cloudResolve rejects an incomplete envelope (missing status_code)', async () => {
  const restore = installFetch(
    () =>
      new Response(JSON.stringify({ headers: { 'content-type': 'application/json' }, body: 'ok' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
  );
  try {
    await cloudResolve('https://resolver.example', 'tok', {
      target_url: 'https://api.example/x',
      method: 'GET',
      headers: {},
      body: '',
    });
    assert.fail('expected an error for a missing status_code');
  } catch (e) {
    assert.ok(e instanceof ApiError);
    assert.match((e as ApiError).message, /incomplete envelope/i);
  } finally {
    restore();
  }
});

test('cloudResolve rejects an oversized body', async () => {
  const restore = installFetch(
    () =>
      new Response(JSON.stringify({ status_code: 200, headers: {}, body: HUGE }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
  );
  try {
    await cloudResolve('https://resolver.example', 'tok', {
      target_url: 'https://api.example/x',
      method: 'GET',
      headers: {},
      body: '',
    });
    assert.fail('expected an error for an oversized body');
  } catch (e) {
    assert.ok(e instanceof ApiError);
    assert.match((e as ApiError).message, /exceeds/);
  } finally {
    restore();
  }
});

test('cloudResolve accepts a well-formed envelope', async () => {
  const restore = installFetch(
    () =>
      new Response(JSON.stringify({ status_code: 200, headers: { 'x-test': '1' }, body: '{"ok":true}' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
  );
  try {
    const r = await cloudResolve('https://resolver.example', 'tok', {
      target_url: 'https://api.example/x',
      method: 'GET',
      headers: {},
      body: '',
    });
    assert.equal(r.status_code, 200);
    assert.equal(r.body, '{"ok":true}');
    assert.equal(r.headers['x-test'], '1');
  } finally {
    restore();
  }
});

test('controlCall rejects an oversized body', async () => {
  const restore = installFetch(
    () =>
      new Response(JSON.stringify({ data: { secrets: { PAD: HUGE } } }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
  );
  try {
    await controlCall('https://api.example/api', 'jwt', 'projects.list', 'GET');
    assert.fail('expected an error for an oversized control-plane body');
  } catch (e) {
    assert.ok(e instanceof ApiError);
    assert.match((e as ApiError).message, /exceeds/);
  } finally {
    restore();
  }
});
