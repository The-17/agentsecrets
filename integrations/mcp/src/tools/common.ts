/**
 * Shared tool plumbing.
 * - dispatch(): local mode execs the CLI helper verb; cloud mode runs the
 *   direct-HTTPS implementation. Both paths return metadata-only results.
 * - withContext(): echoes the resolved project/workspace/environment in
 *   every result (multi-project safety: the model always sees what acted).
 * - sanitize(): defense-in-depth redaction of token-like strings from
 *   unexpected error text before it reaches tool output.
 */

import { bridgeExec, BridgeError } from '../local/binary.js';
import type { CallCtx } from '../resolver/index.js';
import { callControl } from '../resolver/index.js';
import { fail, ok, type ToolResult } from '../resolver/types.js';
import { recordTool, recordError } from '../telemetry.js';

/**
 * Resolve a workspace ref (ID or human name) to a workspace ID.
 * Absent ref → context workspace ID, passed through untouched. Explicit
 * ref → matched against the API workspace list so names never reach
 * `{workspace_id}` URL params (the control plane rejects non-UUIDs with
 * an opaque "Invalid Entry" error). A failed lookup passes the ref
 * through for the server to reject authoritatively; a successful lookup
 * with no match fails here with an actionable message.
 */
export async function resolveWorkspaceId(call: CallCtx, ref?: string): Promise<string> {
  const id = ref ?? call.ctx.project?.workspaceId;
  if (!id) throw new Error('No workspace in context. Pass {workspace}, run from a project directory, or pin defaults via auth_use_identity.');
  if (!ref) return id;
  try {
    const list = (await callControl(call).get('workspaces.list')) as Array<{ id: string; name: string }>;
    const hit = (list ?? []).find((w) => w.id === ref || w.name === ref);
    if (hit) return hit.id;
    throw new Error(`Workspace ${JSON.stringify(ref)} not found. Pass an ID or exact name from workspace_list.`);
  } catch (e) {
    if (e instanceof Error && e.message.startsWith('Workspace ')) throw e;
    return id;
  }
}

export function withContext(call: CallCtx, data: unknown): ToolResult {
  const context = {
    project: call.ctx.project
      ? { id: call.ctx.project.projectId, name: call.ctx.project.projectName }
      : null,
    workspace: call.ctx.project?.workspaceId
      ? { id: call.ctx.project.workspaceId, name: call.ctx.project.workspaceName }
      : null,
    environment: call.ctx.env.name,
    source: call.ctx.env.source,
    mode: call.mode.mode,
  };
  if (data !== null && typeof data === 'object' && !Array.isArray(data)) {
    return ok({ ...(data as Record<string, unknown>), context });
  }
  return ok({ result: data, context });
}

/** Redact anything shaped like a credential from free-form error text. */
export function sanitize(text: string): string {
  return text
    .replace(/agt_[A-Za-z0-9_-]+/g, '[REDACTED]')
    .replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[REDACTED]')
    .replace(/as_sess_[A-Za-z0-9]+/g, '[REDACTED]');
}

export async function dispatch(
  call: CallCtx,
  verb: string,
  args: Record<string, unknown>,
  cloud: () => Promise<ToolResult>
): Promise<ToolResult> {
  if (call.mode.mode === 'local') {
    if (!call.mode.binary) return fail('Local mode selected but no working binary (unexpected). Switch to cloud mode.');
    // Forward the model's requested scope for the helper's expect_* guard.
    // The helper (not this bridge) enforces it against its binding.
    const forwarded: Record<string, unknown> = { ...args };
    if (typeof args['project'] === 'string' && args['project']) forwarded['expect_project'] = args['project'];
    if (typeof args['workspace'] === 'string' && args['workspace']) forwarded['expect_workspace'] = args['workspace'];
    try {
      const env = bridgeExec(call.mode.binary, verb, forwarded, { cwd: call.dir });
      recordTool(verbToTool(verb));
      return withContext(call, env.data ?? null);
    } catch (e) {
      const msg = e instanceof BridgeError ? e.message : e instanceof Error ? e.message : String(e);
      recordTool(verbToTool(verb));
      recordError('unknown');
      return fail(sanitize(msg));
    }
  }
  try {
    const out = await cloud();
    recordTool(verbToTool(verb));
    return out;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    recordTool(verbToTool(verb));
    recordError(classifyError(e));
    return fail(sanitize(msg));
  }
}

/** Map helper verbs back to tool names for telemetry (they align 1:1). */
function verbToTool(verb: string): string {
  return verb.replace('.', '_');
}

function classifyError(e: unknown): 'auth' | 'network' | 'secrets' | 'unknown' {
  if (e && typeof e === 'object' && 'status' in e) {
    const status = (e as { status: unknown }).status;
    if (status === 401 || status === 403) return 'auth';
    if (status === 0) return 'network';
  }
  const msg = e instanceof Error ? e.message : String(e);
  if (/decrypt|ciphertext|workspace data key/i.test(msg)) return 'secrets';
  return 'unknown';
}
