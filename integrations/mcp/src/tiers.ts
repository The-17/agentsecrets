/**
 * Permission tiers for the model-facing surface.
 *
 * An agent is an untrusted control path. A poisoned page, issue, or tool result
 * can instruct it to delete a credential in use, widen an allowlist, or mint a
 * durable token, and none of that needs the plaintext. Value-blindness does not
 * help, because the damage does not depend on seeing a value.
 *
 * This mirrors the Go side (`pkg/mcp/tiers.go` and `cmd/agentsecrets/commands/
 * mcp_bridge.go`) so the guarantee holds in both transports. The Go gate covers
 * local mode; this file covers cloud mode, which talks to the control plane and
 * resolver directly and never passes through the CLI.
 *
 *   read         always available
 *   write        refused unless a human set AGENTSECRETS_MCP_ALLOW_WRITES=true
 *   destructive  same, plus the tool's own confirm argument
 *
 * The switch lives in the process environment of the MCP server, which the
 * client configuration sets and a model cannot. That asymmetry is the boundary.
 */

export type Tier = 'read' | 'write' | 'destructive';

export const ENV_ALLOW_WRITES = 'AGENTSECRETS_MCP_ALLOW_WRITES';

/** True only for the exact value "true". Anything else fails closed. */
export function allowWrites(): boolean {
  return (process.env[ENV_ALLOW_WRITES] ?? '').trim().toLowerCase() === 'true';
}

/**
 * Tier per tool. Every registered tool must appear here; `tierOf` throws on an
 * unknown name so a new tool cannot be registered untiered by accident.
 */
export const TOOL_TIERS: Readonly<Record<string, Tier>> = {
  // Use a credential, never mutate one.
  proxy_call: 'read',
  proxy_status: 'read',
  secrets_list: 'read',
  secrets_diff: 'read',
  secrets_rotation_status: 'read',
  project_list: 'read',
  workspace_list: 'read',
  workspace_members: 'read',
  agent_list: 'read',
  logs_list: 'read',
  logs_summary: 'read',
  logs_detail: 'read',
  auth_status: 'read',
  auth_use_identity: 'read',

  // Session and sync. Reversible, but still a mutation a model should not
  // reach on its own.
  secrets_pull: 'write',
  secrets_push: 'write',
  project_create: 'write',
  project_use: 'write',
  project_update: 'write',
  workspace_create: 'write',
  workspace_switch: 'write',
  auth_login: 'write',
  auth_logout: 'write',

  // Irreversible, access-widening, or mints a durable credential.
  secrets_set: 'destructive',
  secrets_delete: 'destructive',
  secrets_rotate: 'destructive',
  project_delete: 'destructive',
  agent_delete: 'destructive',
  agent_token_issue: 'destructive',
  agent_token_rotate: 'destructive',
};

export function tierOf(tool: string): Tier {
  const tier = TOOL_TIERS[tool];
  if (!tier) {
    throw new Error(
      `internal: tool ${JSON.stringify(tool)} has no permission tier. ` +
        'Add it to TOOL_TIERS before registering it.'
    );
  }
  return tier;
}

/** The CLI command a human should run instead, for the refusal message. */
const HUMAN_COMMAND: Readonly<Record<string, string>> = {
  secrets_set: 'agentsecrets secrets set <KEY> --generate',
  secrets_delete: 'agentsecrets secrets delete <KEY>',
  project_delete: 'agentsecrets project delete <name>',
  agent_delete: 'agentsecrets agent delete <name>',
  agent_token_issue: 'agentsecrets agent token issue <name>',
  secrets_pull: 'agentsecrets secrets pull',
  secrets_push: 'agentsecrets secrets push',
  project_create: 'agentsecrets project create <name>',
  project_use: 'agentsecrets project use <name>',
  project_update: 'agentsecrets project update <name>',
  workspace_create: 'agentsecrets workspace create <name>',
  workspace_switch: 'agentsecrets workspace switch <name>',
  auth_login: 'agentsecrets login',
  auth_logout: 'agentsecrets logout',
};

/**
 * The refusal text, written for the model that receives it. A bare error invites
 * retries and workarounds; naming the human command makes handing it back the
 * obvious move. It must never suggest pasting a value into chat.
 */
export function refusal(tool: string): string {
  const tier = tierOf(tool);
  const human = HUMAN_COMMAND[tool] ?? '<the equivalent agentsecrets command>';
  return (
    `refused: "${tool}" is a ${tier} tool and writes are disabled for agent surfaces. ` +
    'This is a deliberate guard against prompt injection, not a missing feature. ' +
    'Tell the user what you wanted to do and give them this command to run themselves: ' +
    `${human}. ` +
    `If the user genuinely wants agents to write, they can set ${ENV_ALLOW_WRITES}=true ` +
    'in the MCP client configuration and restart the server. ' +
    'You cannot enable it yourself, and you should not ask the user to paste a secret value into chat.'
  );
}

/** Permission state, surfaced by auth_status so the boundary is visible. */
export function tierReport(): Record<string, unknown> {
  const byTier: Record<Tier, string[]> = { read: [], write: [], destructive: [] };
  for (const [name, tier] of Object.entries(TOOL_TIERS)) byTier[tier].push(name);
  for (const list of Object.values(byTier)) list.sort();
  return {
    writes_enabled: allowWrites(),
    enabled_by: ENV_ALLOW_WRITES,
    read: byTier.read,
    write: byTier.write,
    destructive: byTier.destructive,
    note:
      'Write and destructive tools are refused unless a human set ' +
      `${ENV_ALLOW_WRITES}=true in the MCP client configuration. An agent cannot enable them.`,
  };
}
