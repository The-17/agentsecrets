/**
 * Secrets tools (key names only — values NEVER appear in results).
 *
 * - local: CLI helper verbs (keychain-backed, full E2EE, .env + keychain sync).
 * - cloud: control-plane API directly. Writes (set) encrypt client-side
 *   with AES-256-GCM (byte-compatible with the Go CLI) before transit;
 *   pull/push operate on local .env files (no keychain — run
 *   `agentsecrets secrets pull` on a CLI machine to feed the local proxy).
 */

import { z } from 'zod';
import { randomBytes, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { CallCtx } from '../resolver/index.js';
import { callControl } from '../resolver/index.js';
import { fail, type ToolResult } from '../resolver/types.js';
import { dispatch, withContext } from './common.js';
import { needJwt, needWorkspaceKey } from '../resolver/guards.js';
import { encryptSecret, decryptSecret } from '../crypto.js';
import { envPathFor, readDotenv, writeDotenv, deleteDotenvKey } from '../dotenv.js';
import { recordSecretCount } from '../telemetry.js';
import { loadProjectConfig, saveProjectConfig } from '../auth/cliFiles.js';

const execFileAsync = promisify(execFile);

function generateRandomValue(byteLength: number): string {
  return randomBytes(byteLength).toString('base64url');
}

function cryptoRandomId(): string {
  return randomUUID();
}

/** Run a command and return its stdout as the new secret value (never logged). */
async function captureCommand(command: string, extract?: string): Promise<string> {
  const { stdout } = await execFileAsync('sh', ['-c', command], { maxBuffer: 1 << 20 });
  const out = stdout.replace(/\r?\n+$/, '');
  if (!extract) return out;
  try {
    const doc = JSON.parse(out) as Record<string, unknown>;
    let cur: unknown = doc;
    for (const seg of extract.split('.')) {
      const m = cur as Record<string, unknown>;
      cur = m?.[seg];
    }
    if (typeof cur === 'string') return cur;
    if (cur === null || cur === undefined) return '';
    return JSON.stringify(cur);
  } catch {
    return out;
  }
}

const contextFields = {
  project: z.string().optional().describe('Project name or ID (defaults to current context)'),
  workspace: z.string().optional().describe('Workspace name or ID (defaults to current context)'),
  path: z.string().optional().describe('Project directory holding .agentsecrets/project.json'),
};

export const secretsListSchema = z.object({
  ...contextFields,
  environment: z.string().optional().describe('development|staging|production (defaults to active)'),
});
export type SecretsListArgs = z.infer<typeof secretsListSchema>;

export const secretsSetSchema = z.object({
  key: z.string().min(1).describe('Secret key name (e.g. STRIPE_KEY)'),
  value: z.string().describe('Secret value. Travels inside this one call; the server stores only AES-256-GCM ciphertext. Delete this message afterwards.'),
  ...contextFields,
  environment: z.string().optional(),
});
export type SecretsSetArgs = z.infer<typeof secretsSetSchema>;

export const secretsDeleteSchema = z.object({
  key: z.string().min(1),
  ...contextFields,
  environment: z.string().optional(),
  confirm: z.literal(true).describe('Required: acknowledges permanent deletion'),
});
export type SecretsDeleteArgs = z.infer<typeof secretsDeleteSchema>;

export const secretsPullSchema = z.object({
  ...contextFields,
  environment: z.string().optional(),
});
export type SecretsPullArgs = z.infer<typeof secretsPullSchema>;

export const secretsPushSchema = z.object({ ...contextFields });
export type SecretsPushArgs = z.infer<typeof secretsPushSchema>;

export const secretsDiffSchema = z.object({
  ...contextFields,
  environment: z.string().optional(),
});
export type SecretsDiffArgs = z.infer<typeof secretsDiffSchema>;

export const secretsRotateSchema = z.object({
  key: z.string().min(1).describe('Secret key name to rotate (e.g. STRIPE_KEY)'),
  ...contextFields,
  environment: z.string().optional(),
  // Value-blind staging — like the CLI: generate a random value, capture a
  // command's stdout, or pass the raw value inside this single call.
  generate: z.boolean().optional().describe('Mint a random value in-process and stage it (never returned)'),
  length: z.number().int().positive().optional().describe('Bytes for generate (default 32)'),
  command: z.string().optional().describe('Shell command whose stdout is the new value (never logged/returned)'),
  extract: z.string().optional().describe('Dot path to the field holding the value in command output (e.g. "data.key")'),
  value: z.string().optional().describe('New value, travels inside this call only; never logged or returned'),
  reason: z.enum(['routine', 'compromise']).optional().describe('Rotation reason (default routine)'),
  confirm: z.literal(true).describe('Required: acknowledges this stages a new secret version'),
});
export type SecretsRotateArgs = z.infer<typeof secretsRotateSchema>;

export const secretsRotationStatusSchema = z.object({
  key: z.string().min(1),
  ...contextFields,
  environment: z.string().optional(),
});
export type SecretsRotationStatusArgs = z.infer<typeof secretsRotationStatusSchema>;

function needProject(call: CallCtx): { projectId: string } {
  const id = call.ctx.project?.projectId;
  if (!id) throw new Error('No project in context. Pass {project, workspace}, run from a project directory, or pin defaults via auth_use_identity.');
  return { projectId: id };
}

export async function secretsList(call: CallCtx, args: SecretsListArgs): Promise<ToolResult> {
  return dispatch(call, 'secrets.list', { ...args }, async () => {
    const env = args.environment ?? call.ctx.env.name;
    // Offline fallback: .env key names when no control-plane login exists.
    if (!call.creds.token || call.creds.tokenKind !== 'jwt') {
      const file = envPathFor(call.dir, env);
      const names = Object.keys(readDotenv(file)).sort();
      return withContext(call, {
        environment: env,
        keys: names.map((key) => ({ key })),
        count: names.length,
        source: 'dotenv (no control-plane login — pass remote context or auth_login for cloud names)',
      });
    }
    const { projectId } = needProject(call);
    const data = (await callControl(call).get('secrets.list', { project_id: projectId }, { environment: env })) as {
      secrets?: Array<{ key: string; updated_at?: string }>;
    };
    const items = (data.secrets ?? []).map((s) => ({ key: s.key, ...(s.updated_at ? { updated_at: s.updated_at } : {}) }));
    return withContext(call, { environment: env, keys: items, count: items.length, source: 'api' });
  });
}

export async function secretsSet(call: CallCtx, args: SecretsSetArgs): Promise<ToolResult> {
  return dispatch(call, 'secrets.set', { ...args }, async () => {
    needJwt(call.creds);
    const key = needWorkspaceKey(call.creds, 'secrets_set');
    const { projectId } = needProject(call);
    const env = args.environment ?? call.ctx.env.name;
    const encrypted = encryptSecret(args.value, key);
    await callControl(call).post('secrets.create', {
      project_id: projectId,
      environment: env,
      secrets: { [args.key]: encrypted },
    });
    return withContext(call, { status: 'success', key: args.key, environment: env });
  });
}

export async function secretsDelete(call: CallCtx, args: SecretsDeleteArgs): Promise<ToolResult> {
  return dispatch(call, 'secrets.delete', { ...args, confirm: true }, async () => {
    needJwt(call.creds);
    const { projectId } = needProject(call);
    const env = args.environment ?? call.ctx.env.name;
    await callControl(call).del('secrets.delete', { project_id: projectId, environment: env, key: args.key });
    try {
      deleteDotenvKey(envPathFor(call.dir, env), args.key);
    } catch {
      /* best effort */
    }
    return withContext(call, { status: 'success', key: args.key, environment: env });
  });
}

export async function secretsPull(call: CallCtx, args: SecretsPullArgs): Promise<ToolResult> {
  return dispatch(call, 'secrets.pull', { ...args }, async () => {
    needJwt(call.creds);
    const wsKey = needWorkspaceKey(call.creds, 'secrets_pull');
    const { projectId } = needProject(call);
    const env = args.environment ?? call.ctx.env.name;
    const data = (await callControl(call).get('secrets.list', { project_id: projectId }, { environment: env })) as {
      secrets?: Array<{ key: string; value?: string }>;
    };
    const plain: Record<string, string> = {};
    let skipped = 0;
    for (const s of data.secrets ?? []) {
      if (!s.value) {
        skipped++;
        continue;
      }
      try {
        plain[s.key] = decryptSecret(s.value, wsKey);
      } catch {
        skipped++;
      }
    }
    const file = envPathFor(call.dir, env);
    writeDotenv(file, plain);
    recordSecretCount(Object.keys(plain).length);
    const loaded = loadProjectConfig(call.dir);
    if (loaded) {
      saveProjectConfig(call.dir, { ...loaded.config, last_pull: new Date().toISOString() });
    }
    return withContext(call, {
      status: 'success',
      environment: env,
      path: file,
      pulled: Object.keys(plain).length,
      skipped,
      note: 'Wrote .env only. The local proxy reads the OS keychain — run `agentsecrets secrets pull` on a CLI machine to feed it.',
    });
  });
}

export async function secretsPush(call: CallCtx, args: SecretsPushArgs): Promise<ToolResult> {
  return dispatch(call, 'secrets.push', { ...args }, async () => {
    needJwt(call.creds);
    const wsKey = needWorkspaceKey(call.creds, 'secrets_push');
    const { projectId } = needProject(call);
    const env = call.ctx.env.name;
    const file = envPathFor(call.dir, env);
    const local = readDotenv(file);
    const names = Object.keys(local);
    if (names.length === 0) {
      return withContext(call, { status: 'success', environment: env, pushed: 0, note: `No keys in ${file}.` });
    }
    const apiSet: Record<string, string> = {};
    for (const [k, v] of Object.entries(local)) apiSet[k] = encryptSecret(v, wsKey);
    await callControl(call).post('secrets.create', { project_id: projectId, environment: env, secrets: apiSet });
    recordSecretCount(names.length);
    const loaded = loadProjectConfig(call.dir);
    if (loaded) {
      saveProjectConfig(call.dir, { ...loaded.config, last_push: new Date().toISOString() });
    }
    return withContext(call, { status: 'success', environment: env, pushed: names.length });
  });
}

export async function secretsDiff(call: CallCtx, args: SecretsDiffArgs): Promise<ToolResult> {
  return dispatch(call, 'secrets.diff', { ...args }, async () => {
    const env = args.environment ?? call.ctx.env.name;
    const localNames = new Set(Object.keys(readDotenv(envPathFor(call.dir, env))));
    if (!call.creds.token || call.creds.tokenKind !== 'jwt') {
      return withContext(call, {
        environment: env,
        local_only: [...localNames].sort(),
        note: 'No control-plane login — showing local .env names only. Call auth_login to diff against cloud.',
      });
    }
    const { projectId } = needProject(call);
    const data = (await callControl(call).get('secrets.list', { project_id: projectId }, { environment: env })) as {
      secrets?: Array<{ key: string; value?: string }>;
    };
    const cloud = new Map((data.secrets ?? []).map((s) => [s.key, s.value ?? null]));
    const added = [...localNames].filter((k) => !cloud.has(k)).sort();
    const removed = [...cloud.keys()].filter((k) => !localNames.has(k)).sort();
    const unchanged: string[] = [];
    const changed: string[] = [];
    // Value comparison only when the workspace key is available; names only either way.
    const wsKey = call.creds.workspaceKey;
    const localVals = readDotenv(envPathFor(call.dir, env));
    for (const k of localNames) {
      if (!cloud.has(k)) continue;
      if (!wsKey) {
        unchanged.push(k);
        continue;
      }
      try {
        const cloudPlain = decryptSecret(cloud.get(k) ?? '', wsKey);
        if (cloudPlain === (localVals[k] ?? '')) unchanged.push(k);
        else changed.push(k);
      } catch {
        changed.push(k);
      }
    }
    unchanged.sort();
    changed.sort();
    return withContext(call, {
      environment: env,
      added,
      removed,
      changed,
      unchanged,
      in_sync: added.length === 0 && removed.length === 0 && changed.length === 0,
      values_compared: wsKey !== null,
    });
  });
}

export async function secretsRotate(call: CallCtx, args: SecretsRotateArgs): Promise<ToolResult> {
  return dispatch(call, 'secrets.rotate', { ...args, confirm: true }, async () => {
    needJwt(call.creds);
    const { projectId } = needProject(call);
    const env = args.environment ?? call.ctx.env.name;
    const reason = args.reason ?? 'routine';
    if (reason !== 'routine' && reason !== 'compromise') throw new Error('reason must be routine or compromise');

    // Stage a NEW pending version, value-blind. The value never appears in the
    // result or logs. Promotion/rollback stays human-only via the CLI.
    let plaintext: string;
    if (args.generate) {
      plaintext = generateRandomValue(args.length ?? 32);
    } else if (args.command) {
      plaintext = await captureCommand(args.command, args.extract);
    } else if (args.value !== undefined) {
      plaintext = args.value;
    } else {
      throw new Error('Provide one of: generate (bool), command (string), or value (string)');
    }
    if (plaintext === '') throw new Error('empty value: nothing staged');

    const wsKey = needWorkspaceKey(call.creds, 'secrets_rotate');
    const encrypted = encryptSecret(plaintext, wsKey);
    const staged = (await callControl(call).post(
      'secrets.rotate_stage',
      { ciphertext: encrypted, rotation_id: 'mcp-' + cryptoRandomId(), reason },
      { project_id: projectId, environment: env, key: args.key.toUpperCase() }
    )) as { version_id?: string };
    return withContext(call, {
      status: 'staged',
      key: args.key,
      environment: env,
      version: staged.version_id ?? null,
      reason,
      next_step: 'Update the value at the provider out-of-band, then the human promotes with `agentsecrets secrets rotate KEY --promote` (requires the human’s password).',
    });
  });
}

export async function secretsRotationStatus(call: CallCtx, args: SecretsRotationStatusArgs): Promise<ToolResult> {
  return dispatch(call, 'secrets.rotation_status', { ...args }, async () => {
    const { projectId } = needProject(call);
    const env = args.environment ?? call.ctx.env.name;
    const status = (await callControl(call).get(
      'secrets.rotation_status',
      { project_id: projectId, environment: env, key: args.key.toUpperCase() }
    )) as Record<string, unknown>;
    return withContext(call, {
      key: args.key,
      environment: env,
      rotation: status,
      note: 'To rotate, a human runs `agentsecrets secrets rotate KEY [--promote|--rollback|--abort]`. Promotion needs the human’s confirmation and password.',
    });
  });
}

export const secretsDescriptions = {
  secrets_list:
    'FIRST STEP before any credentialed call: discover which secret KEY NAMES exist in a project. ' +
    'Returns names (plus which environment each is in) — values are NEVER returned and cannot be requested. ' +
    'Pass the names you find here to proxy_call. Without a login it falls back to local .env file names.',
  secrets_set:
    'Store a NEW secret value under a key name (e.g. STRIPE_KEY). ' +
    'WHEN: the human gives you a fresh credential to save. ' +
    'The value travels inside this single call and is encrypted before transit; the server keeps ciphertext only. ' +
    'Ask the human to delete the message containing the raw value afterwards.',
  secrets_delete:
    'Permanently delete a secret key everywhere (cloud and local files). ' +
    'WHEN: the human explicitly asks to remove a credential. Requires confirm:true AND the human\u2019s explicit approval in chat — never call this on your own initiative.',
  secrets_pull:
    'Download the project\u2019s secrets into its local .env file (a KEY=VALUE text file, owner-only permissions). ' +
    'WHEN: local files are missing or outdated and code needs to run. ' +
    'Values are decrypted into the file only — they are never returned to you. Needs a workspace key or local mode.',
  secrets_push:
    'Upload the local .env file\u2019s secrets to shared storage so teammates/agents get them. ' +
    'WHEN: the human added keys locally and wants them synced. Values are encrypted before transit. Needs a workspace key or local mode.',
  secrets_diff:
    'Compare local .env key NAMES against shared storage to spot drift (added/removed/changed, names only). ' +
    'WHEN: something works locally but not remotely (or vice versa), or before a pull/push. Values are never shown.',
  secrets_rotation_status:
    'Read a secret’s rotation cadence and version history (metadata only — never values). ' +
    'WHEN: you need to know when a key was last rotated or when it is due. ' +
    'This is a read; it does not change anything. Actual rotation is staged here but promoted by the human via the CLI.',
  secrets_rotate:
    'Stage a NEW pending version of a secret value (value-blind: generate, command, or inline). ' +
    'WHEN: the human wants a key rotated and has handed you a fresh value, or asked you to mint one. ' +
    'The new value is encrypted before transit and is NEVER returned or logged. ' +
    'Promotion (making it live) stays with the human via `agentsecrets secrets rotate KEY --promote` — this tool only stages.',
};
