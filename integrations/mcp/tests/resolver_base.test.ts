import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { RESOLVER_BASE_URL, resolverBaseUrl } from '../src/resolver/index.js';

const OFFICIAL = 'https://resolver.agentsecrets.tech';

describe('resolverBaseUrl (one resolver only)', () => {
  it('is the fixed official host', () => {
    assert.equal(RESOLVER_BASE_URL, OFFICIAL);
    assert.equal(resolverBaseUrl(), OFFICIAL);
  });

  it('ignores the removed AGENTSECRETS_CLOUD_RESOLVER_URL override', () => {
    const key = 'AGENTSECRETS_CLOUD_RESOLVER_URL';
    const previous = process.env[key];
    process.env[key] = 'https://resolver.example';
    try {
      assert.equal(resolverBaseUrl(), OFFICIAL);
    } finally {
      if (previous === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = previous;
      }
    }
  });
});
