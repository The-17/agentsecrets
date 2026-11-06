import { chmodSync, existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

import { AgentSecretsClient } from "../src/client.js";
import { TransportError } from "../src/errors.js";

// Go pins the no-downgrade rule (pkg/gateway/adversarial_test.go): a cloud
// failure must never fall back to local resolution, because that bypasses the
// resolver trust boundary and the billing path. The plugins had no such pin,
// so a future "resilience" refactor could add a silent local fallback and CI
// would stay green. These tests make that refactor fail.

const REQUEST = {
  url: "https://api.example.com/v1/things",
  method: "GET",
  injections: { bearer: "STRIPE_KEY" },
};

/**
 * A sentinel CLI that records any invocation. Cloud mode must never run it; if
 * it does, a local fallback happened and the call escaped the resolver path.
 * AGENTSECRETS_BINARY is set too, so the sentinel is discoverable by mode
 * resolution exactly as it would be in a real fallback.
 */
function sentinel(prefix: string): { binary: string; marker: string; restore: () => void } {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  const marker = join(directory, "local-helper-ran");
  const binary = join(directory, "agentsecrets");
  writeFileSync(binary, `#!/bin/sh\ntouch ${JSON.stringify(marker)}\nexit 0\n`);
  chmodSync(binary, 0o755);

  const previous = process.env.AGENTSECRETS_BINARY;
  process.env.AGENTSECRETS_BINARY = binary;
  const restore = (): void => {
    if (previous === undefined) {
      delete process.env.AGENTSECRETS_BINARY;
    } else {
      process.env.AGENTSECRETS_BINARY = previous;
    }
  };
  return { binary, marker, restore };
}

test("an unreachable resolver fails the call and never downgrades to local", async () => {
  const { binary, marker, restore } = sentinel("as-cloud-fail-");
  try {
    const client = new AgentSecretsClient({
      mode: "cloud",
      token: "workload-token",
      binary,
      resolverUrl: "http://127.0.0.1:1",
      timeoutMs: 2_000,
    });
    assert.equal(client.mode, "cloud");

    await assert.rejects(client.call(REQUEST), TransportError);
    assert.equal(existsSync(marker), false, "cloud failure downgraded to the local helper");
  } finally {
    restore();
  }
});

test("a 5xx from the resolver fails the call and never downgrades to local", async () => {
  const { binary, marker, restore } = sentinel("as-cloud-5xx-");
  const server = createServer((_req, res) => {
    res.statusCode = 503;
    res.end("resolver down");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;

  try {
    const client = new AgentSecretsClient({
      mode: "cloud",
      token: "workload-token",
      binary,
      resolverUrl: `http://127.0.0.1:${port}`,
      timeoutMs: 2_000,
    });

    await assert.rejects(client.call(REQUEST), TransportError);
    assert.equal(existsSync(marker), false, "cloud failure downgraded to the local helper");
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
    restore();
  }
});
