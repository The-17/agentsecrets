import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentSecretsClient } from "../src/client.js";

import {
  AuthenticationError,
  AuthorizationError,
  ConfigurationError,
  InvalidRequest,
  QuotaExceededError,
  TransportError,
  UnsupportedInjection,
} from "../src/errors.js";
import { CloudResolverTransport, LocalHelperTransport, buildResolvePayload } from "../src/transports.js";
import { normalizeRequest } from "../src/types.js";

const HELPER = `
import { readFileSync } from "node:fs";
if (process.argv.slice(2).includes("status")) {
  console.log(JSON.stringify({ ok: true, data: { environment: { active: "staging", source: "test" } } }));
  process.exit(0);
}
const payload = JSON.parse(readFileSync(0, "utf8"));
const body = {
  injections: payload.injections,
  headers: payload.headers,
  agent_id: payload.agent_id,
  environment: payload.environment,
  cloud_token: process.env.AGENTSECRETS_TOKEN ?? "MISSING",
  use_cloud: process.env.AGENTSECRETS_USE_CLOUD ?? "MISSING",
  agent_token: process.env.AS_AGENT_TOKEN ?? "MISSING",
};
console.log(JSON.stringify({
  ok: true,
  data: {
    status_code: 200,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    environment: payload.environment,
  },
}));
`;

async function withHelper<T>(source: string, fn: (script: string) => Promise<T>): Promise<T> {
  const directory = mkdtempSync(join(tmpdir(), "agentsecrets-plugin-"));
  const script = join(directory, "helper.mjs");
  writeFileSync(script, source, "utf8");
  try {
    return await fn(script);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function mismatchHelper(marker: string): string {
  return `
import { appendFileSync } from "node:fs";
if (process.argv.slice(2).includes("status")) {
  console.log(JSON.stringify({ ok: true, data: { environment: { active: "staging" } } }));
  process.exit(0);
}
appendFileSync(${JSON.stringify(marker)}, "called\\n");
console.log(JSON.stringify({ ok: true, data: { status_code: 200, headers: {}, body: "ok" } }));
`;
}

async function withProcessEnv<T>(
  values: Record<string, string>,
  fn: () => Promise<T>,
): Promise<T> {
  const saved = new Map<string, string | undefined>();
  for (const [key, value] of Object.entries(values)) {
    saved.set(key, process.env[key]);
    process.env[key] = value;
  }
  try {
    return await fn();
  } finally {
    for (const [key, value] of saved) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

test("local helper sends key names and scrubs parent secrets", async () => {
  await withHelper(HELPER, async (script) => {
    const transport = new LocalHelperTransport({
      binary: process.execPath,
      args: [script],
      timeoutMs: 5_000,
    });

    const result = await withProcessEnv(
      {
        AGENTSECRETS_TOKEN: "workload-secret",
        AGENTSECRETS_USE_CLOUD: "1",
        AS_AGENT_TOKEN: "agent-token",
        AGENTSECRETS_ENV: "staging",
      },
      () =>
        transport.call(
          normalizeRequest({
            url: "https://api.example.com/v1/things",
            injections: { bearer: "STRIPE_KEY" },
            headers: { "X-Trace": "abc" },
            body: '{"hello":"world"}',
            environment: "staging",
            agent_id: "test-agent",
          }),
        ),
    );

    assert.equal(result.status_code, 200);
    assert.equal(result.environment, "staging");
    assert.equal(result.headers["content-type"], "application/json");
    const sent = JSON.parse(result.body) as Record<string, unknown>;
    assert.deepEqual(sent.injections, { bearer: "STRIPE_KEY" });
    assert.equal(sent.agent_id, "test-agent");
    assert.equal(sent.environment, "staging");
    assert.equal((sent.headers as Record<string, string>)["Content-Type"], "application/json");
    assert.equal(sent.cloud_token, "MISSING");
    assert.equal(sent.use_cloud, "MISSING");
    assert.equal(sent.agent_token, "agent-token");
  });
});

test("local helper reports its active environment", async () => {
  await withHelper(HELPER, async (script) => {
    const transport = new LocalHelperTransport({
      binary: process.execPath,
      args: [script],
      statusArgs: [script, "mcp", "bridge", "status"],
    });
    assert.equal(transport.activeEnvironment(), "staging");
  });
});

test("environment mismatch fails before the proxy call", async () => {
  const directory = mkdtempSync(join(tmpdir(), "agentsecrets-plugin-"));
  const marker = join(directory, "called.txt");
  const script = join(directory, "helper.mjs");
  writeFileSync(script, mismatchHelper(marker), "utf8");
  try {
    const transport = new LocalHelperTransport({
      binary: process.execPath,
      args: [script],
      statusArgs: [script, "mcp", "bridge", "status"],
    });
    const client = new AgentSecretsClient({ transport });

    await assert.rejects(
      client.call({
        url: "https://api.example.com",
        injections: { bearer: "KEY" },
        environment: "production",
      }),
      InvalidRequest,
    );
    assert.equal(existsSync(marker), false);

    const result = await client.call({
      url: "https://api.example.com",
      injections: { bearer: "KEY" },
      environment: "staging",
    });
    assert.equal(result.environment, "staging");
    assert.equal(existsSync(marker), true);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("local helper surfaces an error envelope", async () => {
  await withHelper('console.log(JSON.stringify({ ok: false, error: "boom" }));', async (script) => {
    const transport = new LocalHelperTransport({ binary: process.execPath, args: [script] });
    await assert.rejects(
      transport.call(normalizeRequest({ url: "https://api.example.com", injections: { bearer: "KEY" } })),
      (error: unknown) => error instanceof TransportError && error.message.includes("boom"),
    );
  });
});

test("local helper surfaces non-JSON output", async () => {
  await withHelper('console.log("not-json");', async (script) => {
    const transport = new LocalHelperTransport({ binary: process.execPath, args: [script] });
    await assert.rejects(
      transport.call(normalizeRequest({ url: "https://api.example.com", injections: { bearer: "KEY" } })),
      TransportError,
    );
  });
});

test("local helper surfaces a timeout", async () => {
  await withHelper("setTimeout(() => {}, 5000);", async (script) => {
    const transport = new LocalHelperTransport({
      binary: process.execPath,
      args: [script],
      timeoutMs: 200,
    });
    await assert.rejects(
      transport.call(normalizeRequest({ url: "https://api.example.com", injections: { bearer: "KEY" } })),
      TransportError,
    );
  });
});

test("a missing helper binary is a configuration error", async () => {
  const transport = new LocalHelperTransport({ binary: "/no/such/agentsecrets" });
  await assert.rejects(
    transport.call(normalizeRequest({ url: "https://api.example.com", injections: { bearer: "KEY" } })),
    ConfigurationError,
  );
});

test("resolve payload carries bearer, header, and body handles", () => {
  const payload = buildResolvePayload(
    normalizeRequest({
      url: "https://api.example.com/v1/things",
      injections: {
        bearer: "A_KEY",
        "header:X-Tenant": "B_KEY",
        "body:auth.key": "C_KEY",
      },
      body: '{"name":"example"}',
      environment: "staging",
    }),
  );

  assert.equal(payload.target_url, "https://api.example.com/v1/things");
  const headers = payload.headers as Record<string, string>;
  assert.equal(headers.Authorization, "Bearer {{A_KEY}}");
  assert.equal(headers["X-Tenant"], "{{B_KEY}}");
  assert.equal(headers["Content-Type"], "application/json");
  assert.deepEqual(JSON.parse(payload.body as string), {
    name: "example",
    auth: { key: "{{C_KEY}}" },
  });
  assert.deepEqual(payload.scope, { environment: "staging" });
});

test("resolve payload encodes form handles", () => {
  const payload = buildResolvePayload(
    normalizeRequest({
      url: "https://api.example.com/token",
      injections: { "form:api_key": "KEY" },
      body: "grant_type=client_credentials",
    }),
  );
  assert.equal(payload.body, "grant_type=client_credentials&api_key=%7B%7BKEY%7D%7D");
  assert.equal(
    (payload.headers as Record<string, string>)["Content-Type"],
    "application/x-www-form-urlencoded",
  );
});

test("cloud mode rejects basic and query injections", () => {
  for (const spec of ["basic", "query:api_key"]) {
    assert.throws(
      () =>
        buildResolvePayload(
          normalizeRequest({
            url: "https://api.example.com",
            injections: { [spec]: "KEY" },
          }),
        ),
      UnsupportedInjection,
    );
  }
});

test("cloud mode rejects non-https targets", () => {
  assert.throws(
    () =>
      buildResolvePayload(
        normalizeRequest({ url: "http://api.example.com", injections: { bearer: "KEY" } }),
      ),
    InvalidRequest,
  );
});

test("cloud mode rejects body injection on a non-object", () => {
  assert.throws(
    () =>
      buildResolvePayload(
        normalizeRequest({
          url: "https://api.example.com",
          injections: { "body:key": "KEY" },
          body: "[]",
        }),
      ),
    InvalidRequest,
  );
});

test("cloud transport posts handles with bearer auth", async () => {
  const captured: { url?: string; init: RequestInit | undefined } = { init: undefined };
  const fetchImpl = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    captured.url = String(input);
    captured.init = init;
    return new Response(
      JSON.stringify({
        status_code: 201,
        headers: { "x-request-id": "abc" },
        body: "created",
        redacted: true,
      }),
      { status: 201, headers: { "content-type": "application/json" } },
    );
  };

  const transport = new CloudResolverTransport({
    token: "workload-token",
    resolverUrl: "https://resolver.example",
    timeoutMs: 12_000,
    fetchImpl,
  });
  const result = await transport.call(
    normalizeRequest({
      url: "https://api.example.com",
      injections: { bearer: "KEY" },
      environment: "production",
    }),
  );

  assert.equal(captured.url, "https://resolver.example/v1/resolve");
  assert.equal(captured.init?.method, "POST");
  const headers = new Headers(captured.init?.headers);
  assert.equal(headers.get("Authorization"), "Bearer workload-token");
  const body = JSON.parse(String(captured.init?.body)) as Record<string, unknown>;
  assert.equal((body.headers as Record<string, string>).Authorization, "Bearer {{KEY}}");
  assert.deepEqual(body.scope, { environment: "production" });
  assert.equal(result.status_code, 201);
  assert.equal(result.environment, "production");
  assert.equal(result.redacted, true);
});

test("cloud transport maps auth errors", async () => {
  for (const [status, errorType] of [
    [401, AuthenticationError],
    [403, AuthorizationError],
    [429, QuotaExceededError],
  ] as const) {
    const fetchImpl = async (): Promise<Response> => new Response("nope", { status });
    const transport = new CloudResolverTransport({
      token: "tok",
      resolverUrl: "https://resolver.example",
      fetchImpl,
    });
    await assert.rejects(
      transport.call(normalizeRequest({ url: "https://api.example.com", injections: { bearer: "KEY" } })),
      errorType,
    );
  }
});
