import { existsSync, readFileSync, statSync } from "node:fs";
import { delimiter, join } from "node:path";

import { ConfigurationError } from "./errors.js";

export const DEFAULT_RESOLVER_URL = "https://resolver.agentsecrets.tech";
export const MODES = ["local", "cloud"] as const;
export type PluginMode = (typeof MODES)[number];

export const CHILD_ENV_KEYS = [
  "PATH",
  "HOME",
  "USERPROFILE",
  "HOMEDRIVE",
  "HOMEPATH",
  "APPDATA",
  "LOCALAPPDATA",
  "SystemRoot",
  "COMSPEC",
  "PATHEXT",
  "XDG_RUNTIME_DIR",
  "DBUS_SESSION_BUS_ADDRESS",
  "AGENTSECRETS_ENV",
  "AGENTSECRETS_PROXY_PORT",
  "AGENTSECRETS_KEYCHAIN_CACHE_TTL_MS",
  "AGENTSECRETS_SERVER_URL",
  "AGENTSECRETS_API_URL",
  "AGENTSECRETS_STORAGE_MODE",
  "AS_AGENT_TOKEN",
  "AS_AGENT_TOKEN_FILE",
  "AGENTSECRETS_AGENT_TOKEN",
  "AGENTSECRETS_AGENT_TOKEN_FILE",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TMPDIR",
  "TEMP",
  "TMP",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "no_proxy",
] as const;

export const NEVER_FORWARD = [
  "AGENTSECRETS_TOKEN",
  "AGENTSECRETS_TOKEN_FILE",
  "AGENTSECRETS_USE_CLOUD",
  "AGENTSECRETS_SESSION_TOKEN",
  "AGENTSECRETS_PLUGIN_MODE",
  "AGENTSECRETS_BINARY",
  "AGENTSECRETS_CLOUD_RESOLVER_URL",
] as const;

const NEVER_FORWARD_SET = new Set<string>(NEVER_FORWARD);

export interface ModeConfig {
  mode: PluginMode;
  binary?: string;
  token?: string;
  resolverUrl: string;
}

export interface ResolveModeOptions {
  mode?: string;
  binary?: string;
  token?: string;
  tokenFile?: string;
  resolverUrl?: string;
}

function which(name: string): string | undefined {
  const pathValue = process.env.PATH;
  if (!pathValue) {
    return undefined;
  }
  const extensions =
    process.platform === "win32" ? (process.env.PATHEXT ?? ".EXE;.CMD;.BAT;.COM").split(";") : [""];
  for (const directory of pathValue.split(delimiter)) {
    if (!directory) {
      continue;
    }
    for (const extension of extensions) {
      const candidate = join(directory, name + extension);
      try {
        if (statSync(candidate).isFile()) {
          return candidate;
        }
      } catch {
        // Keep looking.
      }
    }
  }
  return undefined;
}

export function findBinary(explicit?: string): string | undefined {
  const candidate = (explicit ?? process.env.AGENTSECRETS_BINARY ?? "").trim();
  if (candidate) {
    if (existsSync(candidate)) {
      try {
        if (statSync(candidate).isFile()) {
          return candidate;
        }
      } catch {
        // Fall through to PATH lookup.
      }
    }
    return which(candidate);
  }
  return which("agentsecrets");
}

export function readToken(explicit?: string, tokenFile?: string): string | undefined {
  const token = (explicit ?? process.env.AGENTSECRETS_TOKEN ?? "").trim();
  if (token) {
    return token;
  }

  const pathValue = (tokenFile ?? process.env.AGENTSECRETS_TOKEN_FILE ?? "").trim();
  if (!pathValue) {
    return undefined;
  }
  let contents: string;
  try {
    contents = readFileSync(pathValue, "utf8").trim();
  } catch {
    throw new ConfigurationError(`cannot read AGENTSECRETS_TOKEN_FILE at ${pathValue}`);
  }
  if (!contents) {
    throw new ConfigurationError(`AGENTSECRETS_TOKEN_FILE at ${pathValue} is empty`);
  }
  return contents;
}

export function resolveMode(options: ResolveModeOptions = {}): ModeConfig {
  const requested = (options.mode ?? process.env.AGENTSECRETS_PLUGIN_MODE ?? "").trim().toLowerCase();
  if (requested && !MODES.includes(requested as PluginMode)) {
    throw new ConfigurationError(
      `AGENTSECRETS_PLUGIN_MODE must be one of ${MODES.join(", ")}; got ${JSON.stringify(requested)}`,
    );
  }

  const binary = findBinary(options.binary);
  const token = readToken(options.token, options.tokenFile);
  const resolverUrl = (
    options.resolverUrl ??
    process.env.AGENTSECRETS_CLOUD_RESOLVER_URL ??
    DEFAULT_RESOLVER_URL
  ).trim();

  if (requested === "local") {
    if (!binary) {
      throw new ConfigurationError(
        "local mode was requested but no agentsecrets binary was found. " +
          "Install the CLI or set AGENTSECRETS_BINARY.",
      );
    }
    return { mode: "local", binary, resolverUrl };
  }

  if (requested === "cloud") {
    if (!token) {
      throw new ConfigurationError(
        "cloud mode was requested but no workload token was found. " +
          "Set AGENTSECRETS_TOKEN or AGENTSECRETS_TOKEN_FILE.",
      );
    }
    return { mode: "cloud", token, resolverUrl };
  }

  if (binary) {
    return { mode: "local", binary, resolverUrl };
  }
  if (token) {
    return { mode: "cloud", token, resolverUrl };
  }

  throw new ConfigurationError(
    "no AgentSecrets mode is available. Install the agentsecrets CLI for local mode, " +
      "or set AGENTSECRETS_TOKEN or AGENTSECRETS_TOKEN_FILE for cloud mode.",
  );
}

export function buildChildEnv(overrides: Record<string, string> = {}): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of CHILD_ENV_KEYS) {
    const value = process.env[key];
    if (value !== undefined) {
      env[key] = value;
    }
  }

  for (const [key, value] of Object.entries(overrides)) {
    if (!NEVER_FORWARD_SET.has(key)) {
      env[key] = value;
    }
  }
  for (const key of NEVER_FORWARD) {
    delete env[key];
  }
  return env;
}
