/**
 * Bridge telemetry — local aggregation into the CLI's own telemetry file
 * (~/.agentsecrets/telemetry.json), which the CLI syncs within 24h via
 * POST telemetry.sync. Same store, same shape, same sync path: one
 * pipeline, no parallel reporting.
 *
 * Recorded per tool call (both modes):
 *   - command_executions["mcp-bridge.<tool>"]++  (mirrors RecordCommand)
 *   - DeveloperCommands++                        (mirrors RecordCommand)
 *   - integrations_active ∪ ["mcp-bridge"]       (mirrors RecordIntegration)
 *   - errors_{auth,network,secrets,unknown}      (best-effort category)
 *   - project_secret_count on pull/push          (mirrors RecordSecretCount)
 *
 * Deliberately NOT recorded: user email, project/workspace IDs (Go fills
 * those on its own runs via hooks; the bridge leaves them absent), URLs,
 * key names, values, tokens. Payloads are usage counts only.
 *
 * Fail-open: every function swallows errors (telemetry must never break
 * tools). Writes are atomic (tmp + rename). No file locking — lost-update
 * races under concurrency are acceptable for counters, same as the Go
 * side. No network calls are made here; the CLI owns syncing.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { globalDir } from './auth/cliFiles.js';
import { BRIDGE_VERSION } from './version.js';

export type ErrorCategory = 'auth' | 'network' | 'secrets' | 'unknown';

function todayKey(d = new Date()): string {
  return d.toISOString().slice(0, 10);
}

function telemetryFile(): string {
  return path.join(globalDir(), 'telemetry.json');
}

interface DayBucket {
  command_executions?: Record<string, number>;
  integrations_active?: string[];
  developer_commands?: number;
  errors_auth_count?: number;
  errors_network_count?: number;
  errors_secrets_count?: number;
  errors_unknown_count?: number;
  project_secret_count?: number;
  cli_version?: string;
  os?: string;
  arch?: string;
  [k: string]: unknown;
}

interface TelemetryData {
  last_sync?: string;
  daily?: Record<string, DayBucket>;
  [k: string]: unknown;
}

function load(): TelemetryData {
  try {
    const raw = fs.readFileSync(telemetryFile(), 'utf8');
    if (!raw.trim()) return {};
    const parsed = JSON.parse(raw) as TelemetryData;
    if (!parsed || typeof parsed !== 'object') return {};
    return parsed;
  } catch {
    return {};
  }
}

function save(data: TelemetryData): void {
  const file = telemetryFile();
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file + '.tmp', JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(file + '.tmp', file);
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    /* best effort on Windows */
  }
}

function mutate(fn: (day: DayBucket) => void): void {
  try {
    const data = load();
    if (!data.daily || typeof data.daily !== 'object') data.daily = {};
    const key = todayKey();
    const day: DayBucket = data.daily[key] ?? {};
    fn(day);
    data.daily[key] = day;
    save(data);
  } catch {
    /* fail-open: telemetry never breaks tools */
  }
}

/** Mirror Go RecordCommand for one bridge tool invocation. */
export function recordTool(tool: string): void {
  mutate((day) => {
    if (!day.command_executions || typeof day.command_executions !== 'object') day.command_executions = {};
    day.command_executions[`mcp-bridge.${tool}`] = (day.command_executions[`mcp-bridge.${tool}`] ?? 0) + 1;
    day.developer_commands = (day.developer_commands ?? 0) + 1;
    if (!Array.isArray(day.integrations_active)) day.integrations_active = [];
    if (!day.integrations_active.includes('mcp-bridge')) day.integrations_active.push('mcp-bridge');
    if (!day.os) day.os = os.platform();
    if (!day.arch) day.arch = os.arch();
    if (!day.cli_version) day.cli_version = `mcp-bridge/${BRIDGE_VERSION}`;
  });
}

/** Mirror Go RecordError* (subset the bridge can categorize honestly). */
export function recordError(category: ErrorCategory): void {
  const field =
    category === 'auth'
      ? 'errors_auth_count'
      : category === 'network'
        ? 'errors_network_count'
        : category === 'secrets'
          ? 'errors_secrets_count'
          : 'errors_unknown_count';
  mutate((day) => {
    day[field] = ((day[field] as number | undefined) ?? 0) + 1;
  });
}

/** Mirror Go RecordSecretCount after pull/push. */
export function recordSecretCount(count: number): void {
  mutate((day) => {
    day.project_secret_count = count;
  });
}
