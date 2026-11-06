import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

import { CloudResolverTransport } from "../src/transports.js";
import { DEFAULT_RESOLVER_URL } from "../src/env.js";

// The resolver host has exactly one guarded source (DEFAULT_RESOLVER_URL in
// env.ts). Every cloud call goes through the transport, so its default must be
// that same constant. A literal here used to be a second source that no test
// pinned, which meant a host change in env.ts left this transport silently
// talking to the old host while every other surface moved. A value-only
// assertion cannot catch that, because a stale literal has the same value as
// the constant today, so the guard is on the source: no bare host in the file.
test("cloud resolver transport carries no bare resolver host literal", () => {
  // Tests run from the package root (see package.json), so the source sits
  // at src/transports.ts regardless of where the compiled test file lands.
  const source = readFileSync(resolve(process.cwd(), "src", "transports.ts"), "utf8");
  assert.doesNotMatch(
    source,
    /["'`]https:\/\/resolver\./,
    "transports.ts holds its own resolver host: import DEFAULT_RESOLVER_URL instead",
  );
});

test("cloud resolver transport defaults to the single guarded resolver host", () => {
  const transport = new CloudResolverTransport({ token: "workload-token" });
  const resolved = (transport as unknown as { resolverUrl: string }).resolverUrl;
  assert.equal(resolved, DEFAULT_RESOLVER_URL);
});

test("an explicit resolver URL still overrides the default", () => {
  const transport = new CloudResolverTransport({
    token: "workload-token",
    resolverUrl: "https://resolver.example/",
  });
  const resolved = (transport as unknown as { resolverUrl: string }).resolverUrl;
  assert.equal(resolved, "https://resolver.example");
});
