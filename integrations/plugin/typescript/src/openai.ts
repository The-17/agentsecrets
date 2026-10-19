import type { AgentSecretsClient } from "./client.js";
import { TOOL_DESCRIPTION, TOOL_NAME, TOOL_SCHEMA, type ToolSchema } from "./schema.js";

export interface OpenAIFunctionTool {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: ToolSchema["parameters"];
  };
}

export function openAITool(): OpenAIFunctionTool {
  return {
    type: "function",
    function: {
      name: TOOL_NAME,
      description: TOOL_DESCRIPTION,
      parameters: TOOL_SCHEMA.parameters,
    },
  };
}

export function openAIHandler(
  client: AgentSecretsClient,
): (args: Record<string, unknown> | string) => Promise<string> {
  return async (args) => {
    const parsed = typeof args === "string" ? (JSON.parse(args) as Record<string, unknown>) : args;
    return client.toolCall(parsed);
  };
}
