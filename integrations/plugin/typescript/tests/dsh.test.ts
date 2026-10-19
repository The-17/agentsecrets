import assert from "node:assert/strict";
import test from "node:test";

import type { AgentSecretsClient } from "../src/client.js";
import { apply, type DshContext, type DshToolDefinition } from "../src/dsh.js";
import { TOOL_SCHEMA } from "../src/schema.js";

test("dsh plugin registers one tool and returns the client", async () => {
  let capturedName = "";
  let captured: DshToolDefinition | undefined;

  const ctx: DshContext = {
    tool(name, definition) {
      capturedName = name;
      captured = definition;
      return {};
    },
  };
  const client = {
    toolCall: async (args: Record<string, unknown>) => JSON.stringify(args),
  } as unknown as AgentSecretsClient;

  const returned = apply(ctx, { client });

  assert.equal(returned, client);
  assert.equal(capturedName, "agentsecrets_call");
  assert.ok(captured);
  assert.equal(captured.description.length > 0, true);
  assert.deepEqual(captured.parameters, TOOL_SCHEMA.parameters);
  assert.equal(
    await captured.execute({ url: "https://api.example.com" }),
    '{"url":"https://api.example.com"}',
  );
});
