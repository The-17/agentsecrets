import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { cloudResolve, controlCall, ApiError } from '../src/resolver/client.js';

/**
 * Client-side SSRF guard: the cloud resolver and the control plane are the
 * only two hosts this bridge is allowed to talk to. A 3xx from either one is
 * an unreadable answer, not an invitation to follow it somewhere else — the
 * redirect body would carry the same Authorization header to a host that never
 * proved it owns the credential. Both clients must refuse.
 */

interface Endpoint {
  url: string;
  hits: () => number;
  close: () => Promise<void>;
}

function listen(handler: http.RequestListener): Promise<Endpoint> {
  return new Promise((resolve) => {
    let hits = 0;
    const server = http.createServer((req, res) => {
      hits += 1;
      handler(req, res);
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        url: `http://127.0.0.1:${port}`,
        hits: () => hits,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

/** Answers every request with a 302 to the canary. */
function redirector(canary: string): http.RequestListener {
  return (req, res) => {
    const target = new URL(req.url ?? '/', canary);
    res.writeHead(302, { Location: target.toString() });
    res.end();
  };
}

const resolveReq = {
  target_url: 'https://api.example.com/v1/ping',
  method: 'GET',
  headers: {},
  body: '',
};

describe('cloudResolve refuses resolver redirects', () => {
  it('does not follow a 3xx to another host and fails closed', async () => {
    const canary = await listen((_req, res) => res.end('{"status_code":200,"headers":{},"body":"pwned"}'));
    const resolver = await listen(redirector(canary.url));
    try {
      await assert.rejects(
        () => cloudResolve(resolver.url, 'agt_test_token', resolveReq),
        (e: unknown) => {
          assert.ok(e instanceof ApiError, `expected ApiError, got ${String(e)}`);
          assert.equal(e.status, 302);
          return true;
        }
      );
      assert.equal(canary.hits(), 0, 'client followed the resolver redirect and hit the redirect target');
    } finally {
      await resolver.close();
      await canary.close();
    }
  });
});

describe('controlCall refuses control-plane redirects', () => {
  it('does not follow a 3xx to another host and fails closed', async () => {
    const canary = await listen((_req, res) => res.end('{"data":{"secrets":[]}}'));
    const api = await listen(redirector(canary.url));
    try {
      await assert.rejects(
        () => controlCall(api.url, 'user-jwt', 'projects.list', 'GET'),
        (e: unknown) => {
          assert.ok(e instanceof ApiError, `expected ApiError, got ${String(e)}`);
          assert.equal(e.status, 302);
          return true;
        }
      );
      assert.equal(canary.hits(), 0, 'client followed the control-plane redirect and hit the redirect target');
    } finally {
      await api.close();
      await canary.close();
    }
  });
});
