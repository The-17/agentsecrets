/**
 * MCP server wiring: all tools registered unconditionally so the model
 * always sees the full surface. Mode guards live inside handlers
 * (dispatch), which return actionable guidance as isError results.
 *
 * 27 tools: proxy(2) secrets(6) projects(5) workspaces(4) agents(3)
 * logs(3) auth(4).
 *
 * SDK v2 note: registerTool takes the Zod RAW SHAPE (schema.shape), not a
 * ZodObject. Handlers receive (args, ctx); this bridge uses args only.
 */

import { McpServer } from '@modelcontextprotocol/server';
import { type ZodType } from 'zod';
import type { CallCtx } from './resolver/index.js';
import { resolveCallCtx } from './resolver/index.js';
import type { ContextInput } from './context.js';
import { fail, type ToolResult } from './resolver/types.js';
import { sanitize } from './tools/common.js';
import { BRIDGE_VERSION } from './version.js';
import {
  proxyCall, proxyStatus, proxyCallSchema, proxyStatusSchema, proxyCallDescription, proxyStatusDescription,
} from './tools/proxy.js';
import {
  secretsList, secretsSet, secretsDelete, secretsPull, secretsPush, secretsDiff,
  secretsListSchema, secretsSetSchema, secretsDeleteSchema, secretsPullSchema,
  secretsPushSchema, secretsDiffSchema, secretsDescriptions,
} from './tools/secrets.js';
import {
  projectList, projectCreate, projectUse, projectUpdate, projectDelete,
  projectListSchema, projectCreateSchema, projectUseSchema, projectUpdateSchema,
  projectDeleteSchema, projectDescriptions,
} from './tools/projects.js';
import {
  workspaceList, workspaceCreate, workspaceSwitch, workspaceMembers,
  workspaceListSchema, workspaceCreateSchema, workspaceSwitchSchema,
  workspaceMembersSchema, workspaceDescriptions,
} from './tools/workspaces.js';
import {
  agentList, agentDelete, agentTokenIssue,
  agentListSchema, agentDeleteSchema, agentTokenIssueSchema, agentDescriptions,
} from './tools/agents.js';
import {
  logsList, logsSummary, logsDetail,
  logsListSchema, logsSummarySchema, logsDetailSchema, logsDescriptions,
} from './tools/logs.js';
import {
  authStatus, authLogin, authLogout, authUseIdentity,
  authStatusSchema, authLoginSchema, authLogoutSchema, authUseIdentitySchema,
  authDescriptions,
} from './tools/auth.js';

export { BRIDGE_VERSION };

/**
 * Server instructions: the entire manual for an agent that has never heard
 * of AgentSecrets. Sent on initialize; models should treat it as read-first.
 */
export const SERVER_INSTRUCTIONS =
  'AgentSecrets keeps API keys and secrets so AI assistants never have to see them. ' +
  'CORE RULE: you only ever handle secret KEY NAMES (like STRIPE_KEY) — never values. ' +
  'To call an API you pass the key name and target URL; the value is injected outside your reach and only the API response returns. ' +
  'ORGANIZATION: secrets live in PROJECTS, projects live in WORKSPACES (usually one per team), values vary by ENVIRONMENT (development, staging, production). ' +
  'Every result echoes the project/workspace/environment it acted on — verify it matches your intent. ' +
  'STANDARD FLOW: 1) call auth_status first (reports what is connected and the next step). ' +
  '2) discover names with secrets_list, project_list, workspace_list. ' +
  '3) act (proxy_call and others). ' +
  'SAFETY: destructive tools need confirm:true AND the human\u2019s explicit approval in chat — never approve yourself, never assume consent. ' +
  'There is no tool that returns a secret or token value. If a task seems to require seeing one, stop and ask the human.';
export const TOOL_NAMES = [
  'proxy_call', 'proxy_status',
  'secrets_list', 'secrets_set', 'secrets_delete', 'secrets_pull', 'secrets_push', 'secrets_diff',
  'project_list', 'project_create', 'project_use', 'project_update', 'project_delete',
  'workspace_list', 'workspace_create', 'workspace_switch', 'workspace_members',
  'agent_list', 'agent_delete', 'agent_token_issue',
  'logs_list', 'logs_summary', 'logs_detail',
  'auth_status', 'auth_login', 'auth_logout', 'auth_use_identity',
];

function toContextInput(args: Record<string, unknown>): ContextInput {
  const out: ContextInput = {};
  if (typeof args['project'] === 'string') out.project = args['project'];
  if (typeof args['workspace'] === 'string') out.workspace = args['workspace'];
  if (typeof args['path'] === 'string') out.path = args['path'];
  if (typeof args['environment'] === 'string') out.environment = args['environment'];
  return out;
}

type Handler = (call: CallCtx, args: Record<string, unknown>) => Promise<ToolResult>;

export function createBridgeServer(): McpServer {
  const server = new McpServer(
    { name: 'agentsecrets-mcp', version: BRIDGE_VERSION },
    { capabilities: { tools: {} }, instructions: SERVER_INSTRUCTIONS }
  );

  const wrap =
    (handler: Handler) =>
    async (args: Record<string, unknown>): Promise<ToolResult> => {
      try {
        const call = await resolveCallCtx(toContextInput(args ?? {}), process.cwd());
        return await handler(call, args);
      } catch (e) {
        console.error(`[agentsecrets-mcp] tool error: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}`);
        return fail(sanitize(e instanceof Error ? e.message : String(e)));
      }
    };

  // zod v4's `.shape` exposes core ($ZodType) typings while the runtime
  // objects are the classic instances passed to z.object() — exactly what
  // the SDK's `Record<string, ZodType>` overload wants (same zod copy, so
  // structurally identical). One asserted boundary here keeps all 27 call
  // sites clean; drop it if the SDK ever accepts core shapes.
  const t = (name: string, description: string, inputSchema: { readonly [k: string]: object }, handler: Handler): void => {
    server.registerTool(
      name,
      { description, inputSchema: inputSchema as unknown as Record<string, ZodType> },
      wrap(handler)
    );
  };

  for (const tool of REGISTERED_TOOLS) t(tool.name, tool.description, tool.shape, tool.run);

  return server;
}

interface ToolDef {
  name: string;
  description: string;
  shape: { readonly [k: string]: object };
  run: Handler;
}

// Single source of truth for registration AND documentation tests: every
// tool an agent can see is listed here exactly once.
const REGISTERED_TOOLS: ToolDef[] = [
    { name: 'proxy_call', description: proxyCallDescription, shape: proxyCallSchema.shape, run: (c, a) => proxyCall(c, a as never) },
    { name: 'proxy_status', description: proxyStatusDescription, shape: proxyStatusSchema.shape, run: (c) => proxyStatus(c) },

    { name: 'secrets_list', description: secretsDescriptions.secrets_list, shape: secretsListSchema.shape, run: (c, a) => secretsList(c, a as never) },
    { name: 'secrets_set', description: secretsDescriptions.secrets_set, shape: secretsSetSchema.shape, run: (c, a) => secretsSet(c, a as never) },
    { name: 'secrets_delete', description: secretsDescriptions.secrets_delete, shape: secretsDeleteSchema.shape, run: (c, a) => secretsDelete(c, a as never) },
    { name: 'secrets_pull', description: secretsDescriptions.secrets_pull, shape: secretsPullSchema.shape, run: (c, a) => secretsPull(c, a as never) },
    { name: 'secrets_push', description: secretsDescriptions.secrets_push, shape: secretsPushSchema.shape, run: (c, a) => secretsPush(c, a as never) },
    { name: 'secrets_diff', description: secretsDescriptions.secrets_diff, shape: secretsDiffSchema.shape, run: (c, a) => secretsDiff(c, a as never) },

    { name: 'project_list', description: projectDescriptions.project_list, shape: projectListSchema.shape, run: (c, a) => projectList(c, a as never) },
    { name: 'project_create', description: projectDescriptions.project_create, shape: projectCreateSchema.shape, run: (c, a) => projectCreate(c, a as never) },
    { name: 'project_use', description: projectDescriptions.project_use, shape: projectUseSchema.shape, run: (c, a) => projectUse(c, a as never) },
    { name: 'project_update', description: projectDescriptions.project_update, shape: projectUpdateSchema.shape, run: (c, a) => projectUpdate(c, a as never) },
    { name: 'project_delete', description: projectDescriptions.project_delete, shape: projectDeleteSchema.shape, run: (c, a) => projectDelete(c, a as never) },

    { name: 'workspace_list', description: workspaceDescriptions.workspace_list, shape: workspaceListSchema.shape, run: (c, a) => workspaceList(c, a as never) },
    { name: 'workspace_create', description: workspaceDescriptions.workspace_create, shape: workspaceCreateSchema.shape, run: (c, a) => workspaceCreate(c, a as never) },
    { name: 'workspace_switch', description: workspaceDescriptions.workspace_switch, shape: workspaceSwitchSchema.shape, run: (c, a) => workspaceSwitch(c, a as never) },
    { name: 'workspace_members', description: workspaceDescriptions.workspace_members, shape: workspaceMembersSchema.shape, run: (c, a) => workspaceMembers(c, a as never) },

    { name: 'agent_list', description: agentDescriptions.agent_list, shape: agentListSchema.shape, run: (c, a) => agentList(c, a as never) },
    { name: 'agent_delete', description: agentDescriptions.agent_delete, shape: agentDeleteSchema.shape, run: (c, a) => agentDelete(c, a as never) },
    { name: 'agent_token_issue', description: agentDescriptions.agent_token_issue, shape: agentTokenIssueSchema.shape, run: (c, a) => agentTokenIssue(c, a as never) },

    { name: 'logs_list', description: logsDescriptions.logs_list, shape: logsListSchema.shape, run: (c, a) => logsList(c, a as never) },
    { name: 'logs_summary', description: logsDescriptions.logs_summary, shape: logsSummarySchema.shape, run: (c, a) => logsSummary(c, a as never) },
    { name: 'logs_detail', description: logsDescriptions.logs_detail, shape: logsDetailSchema.shape, run: (c, a) => logsDetail(c, a as never) },

    { name: 'auth_status', description: authDescriptions.auth_status, shape: authStatusSchema.shape, run: (c, a) => authStatus(c, a as never) },
    { name: 'auth_login', description: authDescriptions.auth_login, shape: authLoginSchema.shape, run: (c, a) => authLogin(c, a as never) },
    { name: 'auth_logout', description: authDescriptions.auth_logout, shape: authLogoutSchema.shape, run: (c, a) => authLogout(c, a as never) },
    { name: 'auth_use_identity', description: authDescriptions.auth_use_identity, shape: authUseIdentitySchema.shape, run: (c, a) => authUseIdentity(c, a as never) },
  ];

/** Documentation surface: every registered tool name → its description. */
export const TOOL_DESCRIPTIONS: Record<string, string> = Object.fromEntries(
  REGISTERED_TOOLS.map((tool) => [tool.name, tool.description] as const)
);
