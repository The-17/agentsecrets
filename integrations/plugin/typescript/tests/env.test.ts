import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  buildChildEnv,
  findBinary,
  NEVER_FORWARD,
  readToken,
  resolveMode,
} from "../src/env.js";
import { ConfigurationError } from "../src/errors.js";

function withEnv<T>(values: Record<string, string | undefined>, fn: () => T): T {
  const saved = new Map<string, string | undefined>();
  for (const [key, value] of Object.entries(values)) {
    saved.set(key, process.env[key]);
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  try {
    return fn();
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

function cleanModeEnv(): Record<string, string | undefined> {
  return {
    PATH: "",
    AGENTSECRETS_BINARY: undefined,
    AGENTSECRETS_TOKEN: undefined,
    AGENTSECRETS_TOKEN_FILE: undefined,
    AGENTSECRETS_PLUGIN_MODE: undefined,
    AGENTSECRETS_CLOUD_RESOLVER_URL: undefined,
  };
}

test("child env keeps configuration and scrubs cloud secrets", () => {
  const env = withEnv(
    {
      PATH: "/usr/bin",
      AGENTSECRETS_ENV: "staging",
      AGENTSECRETS_PROXY_PORT: "8787",
      AS_AGENT_TOKEN: "agent-token",
      AGENTSECRETS_TOKEN: "workload-token",
      AGENTSECRETS_TOKEN_FILE: "/tmp/token",
      AGENTSECRETS_USE_CLOUD: "1",
      AGENTSECRETS_PLUGIN_MODE: "cloud",
      AGENTSECRETS_BINARY: "/bin/agentsecrets",
      AGENTSECRETS_CLOUD_RESOLVER_URL: "https://resolver.example",
      UNRELATED_SECRET: "nope",
    },
    () => buildChildEnv(),
  );

  assert.equal(env.PATH, "/usr/bin");
  assert.equal(env.AGENTSECRETS_ENV, "staging");
  assert.equal(env.AS_AGENT_TOKEN, "agent-token");
  assert.equal(env.UNRELATED_SECRET, undefined);
  for (const key of NEVER_FORWARD) {
    assert.equal(env[key], undefined);
  }
});

test("overrides cannot reintroduce never-forward keys", () => {
  const env = buildChildEnv({
    AGENTSECRETS_TOKEN: "workload-token",
    AGENTSECRETS_USE_CLOUD: "1",
    CUSTOM: "value",
  });
  assert.equal(env.AGENTSECRETS_TOKEN, undefined);
  assert.equal(env.AGENTSECRETS_USE_CLOUD, undefined);
  assert.equal(env.CUSTOM, "value");
});

test("explicit local mode without a binary fails", () => {
  withEnv(cleanModeEnv(), () => {
    assert.throws(() => resolveMode({ mode: "local" }), ConfigurationError);
  });
});

test("explicit cloud mode without a token fails", () => {
  withEnv(cleanModeEnv(), () => {
    assert.throws(() => resolveMode({ mode: "cloud" }), ConfigurationError);
  });
});

test("invalid mode fails", () => {
  withEnv(cleanModeEnv(), () => {
    assert.throws(() => resolveMode({ mode: "sideways" }), ConfigurationError);
  });
});

test("an explicit binary resolves local mode", () => {
  const directory = mkdtempSync(join(tmpdir(), "agentsecrets-plugin-"));
  try {
    const binary = join(directory, "agentsecrets");
    writeFileSync(binary, "", "utf8");
    const config = withEnv(cleanModeEnv(), () => resolveMode({ binary }));
    assert.equal(config.mode, "local");
    assert.equal(config.binary, binary);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a token resolves cloud mode when no binary exists", () => {
  withEnv(cleanModeEnv(), () => {
    const config = resolveMode({ token: "workload-token" });
    assert.equal(config.mode, "cloud");
    assert.equal(config.token, "workload-token");
  });
});

test("auto mode prefers local over cloud", () => {
  const directory = mkdtempSync(join(tmpdir(), "agentsecrets-plugin-"));
  try {
    const binary = join(directory, "agentsecrets");
    writeFileSync(binary, "", "utf8");
    const config = withEnv(cleanModeEnv(), () =>
      resolveMode({ binary, token: "workload-token" }),
    );
    assert.equal(config.mode, "local");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a token file is read", () => {
  const directory = mkdtempSync(join(tmpdir(), "agentsecrets-plugin-"));
  try {
    const tokenFile = join(directory, "token");
    writeFileSync(tokenFile, "file-token\n", "utf8");
    const token = withEnv(cleanModeEnv(), () => readToken(undefined, tokenFile));
    assert.equal(token, "file-token");
    const config = withEnv(cleanModeEnv(), () => resolveMode({ tokenFile }));
    assert.equal(config.mode, "cloud");
    assert.equal(config.token, "file-token");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a missing token file fails", () => {
  const directory = mkdtempSync(join(tmpdir(), "agentsecrets-plugin-"));
  try {
    withEnv(cleanModeEnv(), () => {
      assert.throws(() => readToken(undefined, join(directory, "missing")), ConfigurationError);
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("findBinary returns undefined for a missing explicit path", () => {
  withEnv(cleanModeEnv(), () => {
    assert.equal(findBinary("/no/such/agentsecrets"), undefined);
  });
});
