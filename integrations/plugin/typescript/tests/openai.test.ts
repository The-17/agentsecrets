import assert from "node:assert/strict";
import test from "node:test";

import type { AgentSecretsClient } from "../src/client.js";
import { openAIHandler, openAITool } from "../src/openai.js";
import { TOOL_SCHEMA } from "../src/schema.js";

test("openAITool exposes the shared function schema", () => {
  const tool = openAITool();
  assert.equal(tool.type, "function");
  assert.equal(tool.function.name, "agentsecrets_call");
  assert.deepEqual(tool.function.parameters, TOOL_SCHEMA.parameters);
});

test("openAIHandler accepts objects and JSON strings", async () => {
  const client = {
    toolCall: async (args: Record<string, unknown>) => JSON.stringify(args),
  } as unknown as AgentSecretsClient;
  const handler = openAIHandler(client);

  assert.equal(
    await handler({ url: "https://api.example.com", injections: { bearer: "KEY" } }),
    '{"url":"https://api.example.com","injections":{"bearer":"KEY"}}',
  );
  assert.equal(
    await handler('{"url":"https://api.example.com"}'),
    '{"url":"https://api.example.com"}',
  );
});
