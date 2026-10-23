import assert from "node:assert/strict";
import test from "node:test";

import { InvalidRequest } from "../src/errors.js";
import {
  localPayload,
  normalizeRequest,
  parseInjections,
  prepareRequest,
  resultToDict,
  type CallResult,
} from "../src/types.js";

test("parses every injection style", () => {
  const parsed = parseInjections({
    bearer: "A_KEY",
    basic: "B_KEY",
    "header:X-Api-Key": "C_KEY",
    "query:api_key": "D_KEY",
    "body:auth.token": "E_KEY",
    "form:api_key": "F_KEY",
  });
  const byStyle = new Map(parsed.map((item) => [item.style, item]));
  assert.equal(byStyle.get("bearer")?.target, "");
  assert.equal(byStyle.get("header")?.target, "X-Api-Key");
  assert.equal(byStyle.get("body")?.target, "auth.token");
  assert.equal(byStyle.get("bearer")?.key, "A_KEY");
});

test("rejects malformed injections", () => {
  assert.throws(() => parseInjections({}), InvalidRequest);
  assert.throws(() => parseInjections({ "bearer:foo": "KEY" }), InvalidRequest);
  assert.throws(() => parseInjections({ "header:": "KEY" }), InvalidRequest);
  assert.throws(() => parseInjections({ magic: "KEY" }), InvalidRequest);
  assert.throws(() => parseInjections({ bearer: "  " }), InvalidRequest);
});

test("normalizes method and injection spec", () => {
  const request = normalizeRequest({
    url: "https://api.example.com",
    method: "post",
    injections: { "Header:X-Api-Key": "KEY" },
  });
  assert.equal(request.method, "POST");
  assert.deepEqual(request.injections, { "header:X-Api-Key": "KEY" });
});

test("adds a JSON content type for JSON bodies", () => {
  const request = prepareRequest(
    normalizeRequest({
      url: "https://api.example.com",
      injections: { bearer: "KEY" },
      body: '{"hello":"world"}',
    }),
  );
  assert.equal(request.headers["Content-Type"], "application/json");
});

test("keeps an existing content type", () => {
  const request = prepareRequest(
    normalizeRequest({
      url: "https://api.example.com",
      injections: { bearer: "KEY" },
      headers: { "content-type": "application/vnd.api+json" },
      body: "{}",
    }),
  );
  assert.equal(request.headers["content-type"], "application/vnd.api+json");
  assert.equal(request.headers["Content-Type"], undefined);
});

test("does not set a content type for non-JSON bodies", () => {
  const request = prepareRequest(
    normalizeRequest({
      url: "https://api.example.com",
      injections: { bearer: "KEY" },
      body: "a=1",
    }),
  );
  assert.equal(request.headers["Content-Type"], undefined);
});

test("accepts custom environment names", () => {
  for (const name of ["qa", "preview-pr-12", "uat"]) {
    const request = normalizeRequest({
      url: "https://api.example.com",
      injections: { bearer: "KEY" },
      environment: name,
    });
    assert.equal(request.environment, name);
  }
});

test("normalizes environment case and whitespace", () => {
  const request = normalizeRequest({
    url: "https://api.example.com",
    injections: { bearer: "KEY" },
    environment: "  QA  ",
  });
  assert.equal(request.environment, "qa");
});

test("rejects invalid environments", () => {
  for (const name of ["", "has space", "-lead", "9qa", "root", "admin", "api", "internal", "default"]) {
    assert.throws(
      () =>
        normalizeRequest({
          url: "https://api.example.com",
          injections: { bearer: "KEY" },
          environment: name,
        }),
      InvalidRequest,
      `expected ${JSON.stringify(name)} to be rejected`,
    );
  }
});

test("accepts camelCase agent ids", () => {
  const request = normalizeRequest({
    url: "https://api.example.com",
    injections: { bearer: "KEY" },
    agentId: "researcher",
  });
  assert.equal(request.agent_id, "researcher");
});

test("rejects non-string injection values", () => {
  assert.throws(
    () =>
      normalizeRequest({
        url: "https://api.example.com",
        injections: { bearer: 1 },
      }),
    InvalidRequest,
  );
});

test("local payload omits empty fields", () => {
  const request = normalizeRequest({
    url: "https://api.example.com",
    injections: { bearer: "KEY" },
  });
  assert.deepEqual(localPayload(request), {
    url: "https://api.example.com",
    method: "GET",
    injections: { bearer: "KEY" },
    agent_id: "plugin",
  });
});

test("resultToDict includes optional metadata", () => {
  const result: CallResult = {
    status_code: 200,
    headers: { "content-type": "application/json" },
    body: "{}",
    environment: "staging",
    redacted: true,
  };
  assert.deepEqual(resultToDict(result), {
    status_code: 200,
    headers: { "content-type": "application/json" },
    body: "{}",
    environment: "staging",
    redacted: true,
  });
});
