import assert from "node:assert/strict";
import test from "node:test";

import { AgentSecretsClient } from "../src/client.js";
import { TOOL_SCHEMA } from "../src/schema.js";
import type { CallResult, NormalizedCallRequest, Transport } from "../src/types.js";

class StubTransport implements Transport {
  readonly requests: NormalizedCallRequest[] = [];

  async call(request: NormalizedCallRequest): Promise<CallResult> {
    this.requests.push(request);
    return {
      status_code: 200,
      headers: { "content-type": "application/json" },
      body: '{"ok":true}',
      ...(request.environment !== undefined ? { environment: request.environment } : {}),
    };
  }
}

test("toolCall returns compact JSON", async () => {
  const transport = new StubTransport();
  const client = new AgentSecretsClient({ transport });

  const output = await client.toolCall({
    url: "https://api.example.com",
    injections: { bearer: "KEY" },
    environment: "staging",
  });

  assert.equal(client.mode, "custom");
  assert.equal(transport.requests.length, 1);
  assert.equal(transport.requests[0]?.agent_id, "plugin");
  assert.deepEqual(JSON.parse(output), {
    status_code: 200,
    headers: { "content-type": "application/json" },
    body: '{"ok":true}',
    environment: "staging",
  });
});

test("schema is the shared contract", () => {
  const client = new AgentSecretsClient({ transport: new StubTransport() });
  assert.deepEqual(client.toolSchema(), TOOL_SCHEMA);
  assert.equal(client.schema.name, "agentsecrets_call");
});

test("toString does not include a token", () => {
  const client = new AgentSecretsClient({ transport: new StubTransport() });
  assert.equal(client.toString(), 'AgentSecretsClient(mode="custom")');
});
