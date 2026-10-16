/**
 * Audit log tools (cloud: control-plane API; local: CLI helper which
 * queries the same remote API). Log rows carry metadata only — secret
 * values never appear in audit records by construction.
 */

import { z } from 'zod';
import type { CallCtx } from '../resolver/index.js';
import { callControl } from '../resolver/index.js';
import { type ToolResult } from '../resolver/types.js';
import { dispatch, resolveWorkspaceId, withContext } from './common.js';
import { needJwt } from '../resolver/guards.js';
import { ApiError } from '../resolver/client.js';

export const logsListSchema = z.object({
  identity: z.string().optional().describe('Filter by agent ID'),
  days: z.number().positive().optional().describe('Look back this many days'),
  limit: z.number().int().positive().max(1000).default(20),
  project: z.string().optional().describe('Project name or ID (defaults to current context)'),
  workspace: z.string().optional(),
});
export type LogsListArgs = z.infer<typeof logsListSchema>;

export const logsSummarySchema = z.object({
  days: z.number().positive().optional(),
  project: z.string().optional(),
  workspace: z.string().optional(),
});
export type LogsSummaryArgs = z.infer<typeof logsSummarySchema>;

export const logsDetailSchema = z.object({
  logId: z.string().min(1).describe('Log entry ID'),
});
export type LogsDetailArgs = z.infer<typeof logsDetailSchema>;

interface ApiLogRow {
  id: string;
  timestamp: string;
  agent_id?: string;
  identity_level?: string;
  credential_ref?: string;
  injection_style?: string;
  target_domain?: string;
  target_url?: string;
  method?: string;
  status_code?: number;
  duration_ms?: number;
  redacted?: boolean;
  resolution_path?: string;
  error?: string;
}

/** Remote row -> safe shape (mirrors Go apiRowToAuditEvent; no values exist). */
function safeRow(r: ApiLogRow): Record<string, unknown> {
  const secretKeys = r.credential_ref ? r.credential_ref.split(',').filter(Boolean) : [];
  const authStyles = r.injection_style ? r.injection_style.split(',').filter(Boolean) : [];
  return {
    id: r.id,
    timestamp: r.timestamp,
    agent_id: r.agent_id ?? '',
    identity_level: r.identity_level ?? '',
    secret_keys: secretKeys,
    auth_styles: authStyles,
    target_url: r.target_url ?? '',
    domain: r.target_domain ?? '',
    method: r.method ?? '',
    status_code: r.status_code ?? 0,
    duration_ms: r.duration_ms ?? 0,
    status: (r.status_code ?? 0) >= 400 || r.error ? 'FAILED' : 'OK',
    reason: r.error ?? '',
    redacted: r.redacted === true,
    resolution_path: r.resolution_path ?? '',
  };
}

function sinceIso(days?: number): string | undefined {
  if (!days) return undefined;
  return new Date(Date.now() - days * 24 * 3600 * 1000).toISOString();
}

export async function logsList(call: CallCtx, args: LogsListArgs): Promise<ToolResult> {
  const limit = args.limit ?? 20;
  return dispatch(call, 'logs.list', { ...args }, async () => {
    needJwt(call.creds);
    const wsId = await resolveWorkspaceId(call, args.workspace);
    const query: Record<string, string> = { workspace_id: wsId, limit: String(limit) };
    if (call.ctx.project?.projectId) query['project_id'] = call.ctx.project.projectId;
    if (args.identity) query['agent_id'] = args.identity;
    const since = sinceIso(args.days);
    if (since) query['since'] = since;
    const rows = ((await callControl(call).get('log.list', undefined, query)) as ApiLogRow[]) ?? [];
    return withContext(call, { workspace_id: wsId, logs: rows.map(safeRow) });
  });
}

export async function logsSummary(call: CallCtx, args: LogsSummaryArgs): Promise<ToolResult> {
  return dispatch(call, 'logs.summary', { ...args }, async () => {
    needJwt(call.creds);
    const wsId = await resolveWorkspaceId(call, args.workspace);
    const query: Record<string, string> = { workspace_id: wsId };
    if (call.ctx.project?.projectId) query['project_id'] = call.ctx.project.projectId;
    const since = sinceIso(args.days);
    if (since) query['since'] = since;
    try {
      const summary = await callControl(call).get('log.summary', undefined, query);
      return withContext(call, { workspace_id: wsId, summary });
    } catch (e) {
      if (!(e instanceof ApiError) || (e.status !== 404 && e.status !== 405)) throw e;
      // Fallback: aggregate client-side over the list endpoint.
      const rows = ((await callControl(call).get(
        'log.list',
        undefined,
        { ...query, limit: '1000' }
      )) as ApiLogRow[]) ?? [];
      const domains = new Set<string>();
      const creds = new Set<string>();
      let blocked = 0;
      let redacted = 0;
      for (const r of rows) {
        if (r.target_domain) domains.add(r.target_domain);
        for (const k of r.credential_ref ? r.credential_ref.split(',') : []) if (k) creds.add(k);
        if ((r.status_code ?? 0) === 403) blocked++;
        if (r.redacted) redacted++;
      }
      return withContext(call, {
        workspace_id: wsId,
        summary: {
          total_calls: rows.length,
          unique_domains: domains.size,
          unique_credentials: creds.size,
          blocked_requests: blocked,
          redacted_events: redacted,
          aggregated: 'client-side fallback',
        },
      });
    }
  });
}

export async function logsDetail(call: CallCtx, args: LogsDetailArgs): Promise<ToolResult> {
  return dispatch(call, 'logs.detail', { ...args }, async () => {
    needJwt(call.creds);
    const row = (await callControl(call).get('log.detail', { log_id: args.logId })) as ApiLogRow;
    return withContext(call, safeRow(row));
  });
}

export const logsDescriptions = {
  logs_list:
    'Read the audit trail: which agent called which API with which key names, when, and whether it was allowed. ' +
    'Metadata only — responses and values are never logged anywhere, so there is nothing sensitive to find here. ' +
    'WHEN: the human asks "what happened", or a call failed and you need the reason. Filter by agent, recency, count.',
  logs_summary:
    'Totals over the audit trail: call counts, distinct APIs and keys used, blocked and redacted counts. ' +
    'WHEN: the human wants an overview ("how much are we using this", "anything blocked lately").',
  logs_detail:
    'Fetch one audit entry by its ID for the full metadata record. ' +
    'WHEN: logs_list surfaced something worth inspecting closely.',
};
