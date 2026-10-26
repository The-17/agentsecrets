/**
 * Local binary backend: spawns `agentsecrets mcp <verb>` with the
 * JSON args on stdin and parses the stdout envelope. The helper inherits the CLI's keychain
 * session, proxy session token, token refresh, and E2EE workspace keys
 * through its own (registered, trusted) binary identity — the bridge
 * process itself holds NO credentials in this mode, only key names and
 * the helper's JSON results.
 *
 * Security note: stdout is machine JSON (single envelope object);
 * diagnostics go to stderr and are surfaced only on failure, truncated.
 * Secret values never appear in argv (passed inside the JSON payload —
 * same as the CLI's own `secrets set KEY=VALUE` semantics) and never in
 * tool results (the bridge decides what reaches the LLM: metadata only).
 */

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

export interface BridgeEnvelope {
  ok: boolean;
  data?: unknown;
  error?: string;
}

export class BridgeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BridgeError';
  }
}

function isExecutable(file: string): boolean {
  try {
    fs.accessSync(file, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** Locate the CLI binary: explicit override, then PATH scan. */
export function findBinary(): string | null {
  const override = process.env['AGENTSECRETS_BINARY']?.trim();
  if (override) {
    if (isExecutable(override)) return override;
    console.error(`[agentsecrets-mcp] AGENTSECRETS_BINARY=${override} is not executable.`);
    return null;
  }
  const pathEnv = process.env['PATH'] ?? '';
  const dirs = pathEnv.split(path.delimiter).filter(Boolean);
  const names = process.platform === 'win32' ? ['agentsecrets.exe', 'agentsecrets.cmd', 'agentsecrets'] : ['agentsecrets'];
  for (const dir of dirs) {
    for (const name of names) {
      const full = path.join(dir, name);
      try {
        if (fs.statSync(full).isFile() && (process.platform === 'win32' || isExecutable(full))) {
          return full;
        }
      } catch {
        /* keep scanning */
      }
    }
  }
  return null;
}

export interface PingInfo {
  binary: string;
  version: string;
  verbs: string[];
  keychain: boolean;
}

let pingCache: { at: number; info: PingInfo } | null = null;
const PING_TTL_MS = 60 * 1000;

/** Capability handshake (`mcp ping`), cached 60s. Null = unusable. */
export function pingBinary(binary?: string): PingInfo | null {
  const now = Date.now();
  if (pingCache && now - pingCache.at < PING_TTL_MS) return pingCache.info;
  const bin = binary ?? findBinary();
  if (!bin) return null;
  try {
    const env = bridgeExec(bin, 'ping', {}, { timeoutMs: 15000 });
    const data = (env.data ?? {}) as Record<string, unknown>;
    const info: PingInfo = {
      binary: bin,
      version: typeof data['version'] === 'string' ? data['version'] : 'unknown',
      verbs: Array.isArray(data['verbs']) ? (data['verbs'] as string[]) : [],
      keychain: data['keychain'] === true,
    };
    pingCache = { at: now, info };
    return info;
  } catch {
    return null;
  }
}

export function clearPingCache(): void {
  pingCache = null;
}

export interface ExecOptions {
  cwd?: string;
  timeoutMs?: number;
}

/**
 * Run one bridge verb. Throws BridgeError on transport failure or when
 * the helper reports {ok:false}. Returns the unwrapped `data`.
 */
export function bridgeExec(binary: string, verb: string, args: Record<string, unknown>, opts: ExecOptions = {}): BridgeEnvelope {
  const payload = JSON.stringify(args);
  // Args travel via STDIN, not argv: the helper reads piped stdin when the
  // JSON argv is absent. This keeps secret values (secrets.set) out of the
  // process table AND sidesteps every platform's argv quoting (notably
  // cmd.exe quote-stripping for .cmd shims).
  const argv = ['mcp', verb];
  // Script shims (.cmd/.bat from the npm wrapper, .ps1, bare node scripts)
  // cannot be exec'd directly on Windows — run them through a shell and let
  // Node do the platform quoting. Real binaries (.exe/ELF/Mach-O) spawn direct.
  const lower = binary.toLowerCase();
  const isScript =
    lower.endsWith('.cmd') || lower.endsWith('.bat') || lower.endsWith('.ps1') ||
    lower.endsWith('.js') || lower.endsWith('.mjs') || lower.endsWith('.cjs');
  let out: ReturnType<typeof spawnSync>;
  try {
    out = spawnSync(binary, argv, {
      cwd: opts.cwd ?? process.cwd(),
      timeout: opts.timeoutMs ?? 60000,
      encoding: 'utf8',
      windowsHide: true,
      input: payload,
      ...(isScript && process.platform === 'win32' ? { shell: true } : {}),
    });
  } catch (e) {
    throw new BridgeError(`failed to launch ${binary}: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (out.error) {
    throw new BridgeError(`failed to launch ${binary}: ${(out.error as Error).message}`);
  }
  const stdout = typeof out.stdout === 'string' ? out.stdout.trim() : '';
  const stderr = typeof out.stderr === 'string' ? out.stderr.trim() : '';
  if (out.status !== 0 && !stdout) {
    const tail = stderr.split('\n').slice(-5).join('\n');
    throw new BridgeError(`agentsecrets mcp ${verb} exited ${String(out.status)}${tail ? `: ${tail}` : ''}`);
  }
  let env: BridgeEnvelope;
  try {
    env = JSON.parse(stdout || '{}') as BridgeEnvelope;
  } catch {
    throw new BridgeError(
      `agentsecrets mcp ${verb} returned non-JSON stdout${stderr ? ` (stderr: ${stderr.slice(0, 300)})` : ''}`
    );
  }
  if (!env || typeof env.ok !== 'boolean') {
    throw new BridgeError(`agentsecrets mcp ${verb} returned a malformed envelope.`);
  }
  if (!env.ok) {
    throw new BridgeError(typeof env.error === 'string' && env.error ? env.error : `${verb} failed`);
  }
  if (stderr) console.error(`[agentsecrets-mcp] bridge ${verb} stderr: ${stderr.slice(0, 500)}`);
  return env;
}
