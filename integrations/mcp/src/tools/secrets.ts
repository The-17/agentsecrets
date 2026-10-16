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
import type { CallCtx } from '../resolver/index.js';
import { callControl } from '../resolver/index.js';
import { fail, type ToolResult } from '../resolver/types.js';
import { dispatch, withContext } from './common.js';
import { needJwt, needWorkspaceKey } from '../resolver/guards.js';
import { encryptSecret, decryptSecret } from '../crypto.js';
import { envPathFor, readDotenv, writeDotenv, deleteDotenvKey } from '../dotenv.js';
import { recordSecretCount } from '../telemetry.js';
import { loadProjectConfig, saveProjectConfig } from '../auth/cliFiles.js';

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
};
