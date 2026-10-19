import { AgentSecretsClient, type ClientOptions } from "./client.js";
import { TOOL_DESCRIPTION, TOOL_NAME, TOOL_SCHEMA, type ToolSchema } from "./schema.js";

export interface DshToolDefinition {
  description: string;
  parameters?: ToolSchema["parameters"];
  execute: (args: Record<string, unknown>) => Promise<unknown>;
}

export interface DshContext {
  tool(name: string, definition: DshToolDefinition): unknown;
}

export interface DshPluginOptions extends ClientOptions {
  client?: AgentSecretsClient;
}

export function apply(ctx: DshContext, options: DshPluginOptions = {}): AgentSecretsClient {
  const { client: supplied, ...clientOptions } = options;
  const client = supplied ?? new AgentSecretsClient(clientOptions);

  ctx.tool(TOOL_NAME, {
    description: TOOL_DESCRIPTION,
    parameters: TOOL_SCHEMA.parameters,
    execute: (args) => client.toolCall(args),
  });
  return client;
}

export const name = "agentsecrets";
export default apply;
