import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { toResolveRequest } from '../src/tools/proxy.js';

const base = {
  url: 'https://api.example.com/v1/charges',
  method: 'GET' as const,
  injections: {} as Record<string, string>,
};

describe('cloud handle translation ({{KEY}} substitution server-side)', () => {
  it('bearer -> Authorization header handle', () => {
    const r = toResolveRequest({ ...base, injections: { bearer: 'STRIPE_KEY' } });
    assert.equal(r.headers['Authorization'], 'Bearer {{STRIPE_KEY}}');
  });
  it('header/body mappings', () => {
    const r = toResolveRequest({
      ...base,
      injections: { 'header:X-Api-Key': 'K1', 'body:auth.key': 'K2' },
      body: '{"auth":{}}',
    });
    assert.equal(r.headers['X-Api-Key'], '{{K1}}');
    assert.deepEqual(JSON.parse(r.body), { auth: { key: '{{K2}}' } });
  });
  it('form builds urlencoded bodies', () => {
    const r = toResolveRequest({ ...base, injections: { 'form:api_key': 'K' } });
    assert.equal(r.body, 'api_key=%7B%7BK%7D%7D');
    assert.equal(r.headers['Content-Type'], 'application/x-www-form-urlencoded');
  });
  it('basic + query are rejected (not expressible server-side)', () => {
    assert.throws(() => toResolveRequest({ ...base, injections: { basic: 'K' } }), /basic-auth.*local mode/);
    assert.throws(() => toResolveRequest({ ...base, injections: { query: 'k' } }), /query-param.*local mode/);
  });
  it('unknown styles rejected', () => {
    assert.throws(() => toResolveRequest({ ...base, injections: { magic: 'K' } }), /unknown injection style/);
  });
  it('non-HTTPS targets rejected client-side', () => {
    assert.throws(
      () => toResolveRequest({ ...base, url: 'http://insecure.example.com/', injections: { bearer: 'K' } }),
      /https/
    );
  });
  it('body injection needs a JSON object body', () => {
    assert.throws(
      () => toResolveRequest({ ...base, body: 'not-json', injections: { 'body:a': 'K' } }),
      /JSON object body/
    );
  });
  it('handle-ish values in extra headers pass through untouched', () => {
    const r = toResolveRequest({ ...base, headers: { 'X-Trace': 'abc' }, injections: { bearer: 'K' } });
    assert.equal(r.headers['X-Trace'], 'abc');
    assert.equal(r.target_url, base.url);
    assert.equal(r.method, 'GET');
  });
});
