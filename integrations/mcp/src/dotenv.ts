/**
 * .env file management — CLOUD MODE ONLY (headless operation without the CLI).
 * Mirrors pkg/secrets/dotenv.go (EnvManager) so .env files stay mutually
 * intelligible with the CLI: `.env` for development, `.env.<environment>`
 * otherwise, rooted at the project root, merge-writes preserving comments,
 * values with spaces/# double-quoted, 0600 permissions.
 *
 * In LOCAL mode the bridge never touches this module: the CLI helper owns
 * all local file/keychain behavior including storage-mode selection
 * (keychain vs env_file). This module exists so binary-less contexts
 * (CI, remote agents, storage_mode=2 style file workflows) can still
 * pull/push/diff against .env files.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { findProjectRoot } from './auth/cliFiles.js';

const ENV_LINE = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/;

export function envPathFor(cwd: string, environment: string): string {
  const found = findProjectRoot(cwd);
  const root = found ?? path.resolve(cwd);
  const filename = environment === 'development' ? '.env' : `.env.${environment}`;
  return path.join(root, filename);
}

export function parseDotenvValue(val: string): string {
  let v = val.trim();
  if (!v) return '';
  const q = v[0];
  if (q === '"' || q === "'") {
    for (let i = 1; i < v.length; i++) {
      if (v[i] === q && v[i - 1] !== '\\') return v.slice(1, i);
    }
  }
  const hash = v.indexOf('#');
  if (hash >= 0) return v.slice(0, hash).trim();
  return v;
}

export function readDotenv(file: string): Record<string, string> {
  const out: Record<string, string> = {};
  let raw: string;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch {
    return out;
  }
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const m = ENV_LINE.exec(line);
    const key = m?.[1];
    if (!key) continue;
    out[key] = parseDotenvValue(m?.[2] ?? '');
  }
  return out;
}

function formatValue(val: string): string {
  if (val.includes(' ') || val.includes('#')) return `"${val}"`;
  return val;
}

/** Merge newSecrets into file, preserving comments/order (mirrors updateFile). */
export function writeDotenv(file: string, newSecrets: Record<string, string>): void {
  const lines: string[] = [];
  const seen = new Set<string>();
  let existing = '';
  try {
    existing = fs.readFileSync(file, 'utf8');
  } catch {
    existing = '';
  }
  if (existing) {
    for (const line of existing.split('\n')) {
      const m = ENV_LINE.exec(line);
      const key = m?.[1];
      if (key && key in newSecrets) {
        let comment = '';
        const hash = (m?.[2] ?? '').indexOf('#');
        if (hash >= 0) comment = ' ' + (m?.[2] ?? '').slice(hash).trim();
        lines.push(`${key}=${formatValue(newSecrets[key] ?? '')}${comment}`);
        seen.add(key);
        continue;
      }
      if (key) seen.add(key);
      lines.push(line);
    }
  }
  for (const [k, v] of Object.entries(newSecrets)) {
    if (!seen.has(k)) lines.push(`${k}=${formatValue(v)}`);
  }
  // Drop a single trailing empty element produced by a final newline.
  while (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file + '.tmp', lines.join('\n') + '\n', { mode: 0o600 });
  fs.renameSync(file + '.tmp', file);
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    /* best effort on Windows */
  }
}

/** Remove one key from the env file (mirrors removeFromFile). */
export function deleteDotenvKey(file: string, key: string): void {
  let raw: string;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch {
    return;
  }
  const kept = raw.split('\n').filter((line) => {
    const m = ENV_LINE.exec(line);
    return !m || m[1] !== key;
  });
  while (kept.length > 0 && kept[kept.length - 1] === '') kept.pop();
  fs.writeFileSync(file, kept.join('\n') + (kept.length ? '\n' : ''), { mode: 0o600 });
}
