export const TOOL_NAME = "agentsecrets_call";
export const TOOL_DESCRIPTION =
  "Call an HTTPS API with AgentSecrets-injected credentials. " +
  "Pass secret KEY NAMES only. Values never enter the model or this tool.";

export interface ToolSchema {
  name: string;
  description: string;
  parameters: {
    type: "object";
    additionalProperties: boolean;
    required: string[];
    properties: Record<string, unknown>;
  };
}

export const TOOL_SCHEMA: ToolSchema = {
  name: TOOL_NAME,
  description: TOOL_DESCRIPTION,
  parameters: {
    type: "object",
    additionalProperties: false,
    required: ["url", "injections"],
    properties: {
      url: { type: "string", description: "Target HTTPS URL." },
      method: {
        type: "string",
        enum: ["GET", "POST", "PUT", "PATCH", "DELETE"],
        default: "GET",
      },
      injections: {
        type: "object",
        description:
          "Map of injection spec to secret KEY NAME. Specs: bearer, basic, " +
          "header:Name, query:param, body:json.path, form:field. Never pass a value.",
        additionalProperties: { type: "string" },
        minProperties: 1,
      },
      headers: {
        type: "object",
        description: "Extra non-credential request headers.",
        additionalProperties: { type: "string" },
      },
      body: {
        type: "string",
        description: "Request body as a string. Use JSON for body: and form: injections.",
      },
      environment: {
        type: "string",
        enum: ["development", "staging", "production"],
        description:
          "Asserts the expected environment. Cloud checks the token binding; " +
          "local checks the active CLI environment.",
      },
      path: {
        type: "string",
        description: "Local project directory. Defaults to the process working directory.",
      },
      agent_id: {
        type: "string",
        description: "Agent name for audit attribution. Defaults to plugin.",
      },
    },
  },
};

export function toolSchema(): ToolSchema {
  return structuredClone(TOOL_SCHEMA);
}
