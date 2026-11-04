import assert from "node:assert/strict";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

import { TransportError } from "../src/errors.js";
import { CloudResolverTransport } from "../src/transports.js";
import { normalizeRequest } from "../src/types.js";

/**
 * A resolver 3xx must not be followed. Following it resends the workload
 * token to a host that never proved it owns the credential (client-side
 * SSRF). The transport has one fixed origin, so a redirect is a protocol
 * error and the call fails closed.
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
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        url: `http://127.0.0.1:${port}`,
        hits: () => hits,
        close: () => new Promise<void>((done) => server.close(() => done())),
      });
    });
  });
}

test("cloud transport refuses a resolver redirect", async () => {
  const canary = await listen((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ status_code: 200, headers: {}, body: "pwned" }));
  });
  const resolver = await listen((req, res) => {
    const target = new URL(req.url ?? "/", canary.url);
    res.writeHead(302, { Location: target.toString() });
    res.end();
  });

  const transport = new CloudResolverTransport({ token: "workload-token", resolverUrl: resolver.url });
  try {
    await assert.rejects(
      transport.call(normalizeRequest({ url: "https://api.example.com", injections: { bearer: "KEY" } })),
      TransportError,
    );
    assert.equal(canary.hits(), 0, "transport followed the resolver redirect and hit the redirect target");
  } finally {
    await resolver.close();
    await canary.close();
  }
});
