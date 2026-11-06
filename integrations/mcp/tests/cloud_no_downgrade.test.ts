import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { ApiError, cloudResolve } from '../src/resolver/client.js';

// Go pins the no-downgrade rule (pkg/gateway/adversarial_test.go): a cloud
// failure must never fall back to local resolution, because that bypasses the
// resolver trust boundary and the billing path. The MCP bridge had no such pin.
// `cloudResolve` is the seam a "resilience" refactor would wrap in a fallback,
// so these tests fail the moment it stops throwing.

const REQUEST = {
  target_url: 'https://api.example.com/v1/things',
  method: 'GET',
  headers: {},
  body: '',
};

describe('cloudResolve never degrades a failure into an answer', () => {
  it('throws on an unreachable resolver', async () => {
    await assert.rejects(cloudResolve('http://127.0.0.1:1', 'workload-token', REQUEST, 2_000), (error: unknown) => {
      assert.ok(error instanceof ApiError);
      assert.equal((error as ApiError).status, 0);
      return true;
    });
  });

  it('throws on a 5xx from the resolver', async () => {
    const server = createServer((_req, res) => {
      res.statusCode = 503;
      res.end('resolver down');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;

    try {
      await assert.rejects(
        cloudResolve(`http://127.0.0.1:${port}`, 'workload-token', REQUEST, 2_000),
        (error: unknown) => {
          assert.ok(error instanceof ApiError);
          assert.equal((error as ApiError).status, 503);
          return true;
        },
      );
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });

  it('throws on an incomplete success envelope instead of returning a status-0 result', async () => {
    const server = createServer((_req, res) => {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ body: 'no status_code here' }));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;

    try {
      await assert.rejects(cloudResolve(`http://127.0.0.1:${port}`, 'workload-token', REQUEST, 2_000), ApiError);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });
});
