import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import { TOOL_SCHEMA, toolSchema } from "../src/schema.js";

test("schema matches the shared fixture", () => {
  const fixture = JSON.parse(readFileSync(resolve(process.cwd(), "../schema/tool.json"), "utf8")) as unknown;
  assert.deepEqual(TOOL_SCHEMA, fixture);
});

test("toolSchema returns a defensive copy", () => {
  const copy = toolSchema();
  copy.name = "changed";
  assert.equal(TOOL_SCHEMA.name, "agentsecrets_call");
});
