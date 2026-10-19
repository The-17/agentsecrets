import { ConfigurationError, InvalidRequest } from "./errors.js";
import { resolveMode } from "./env.js";
import { TOOL_SCHEMA, toolSchema, type ToolSchema } from "./schema.js";
import { CloudResolverTransport, LocalHelperTransport } from "./transports.js";
import type { CallRequest, CallResult, NormalizedCallRequest, Transport } from "./types.js";
import { normalizeRequest } from "./types.js";

export interface ClientOptions {
  mode?: string;
  binary?: string;
  token?: string;
  tokenFile?: string;
  resolverUrl?: string;
  timeoutMs?: number;
  transport?: Transport;
  env?: Record<string, string>;
}

export class AgentSecretsClient {
  private readonly transport: Transport;
  private readonly modeValue: string;

  constructor(options: ClientOptions = {}) {
    if (options.transport) {
      this.transport = options.transport;
      this.modeValue = "custom";
      return;
    }

    const config = resolveMode(options);
    if (config.mode === "local") {
      if (!config.binary) {
        throw new ConfigurationError("local mode resolved without an agentsecrets binary");
      }
      this.transport = new LocalHelperTransport({
        binary: config.binary,
        ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
        ...(options.env !== undefined ? { env: options.env } : {}),
      });
      this.modeValue = "local";
      return;
    }

    if (!config.token) {
      throw new ConfigurationError("cloud mode resolved without a workload token");
    }
    this.transport = new CloudResolverTransport({
      token: config.token,
      resolverUrl: config.resolverUrl,
      ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
    });
    this.modeValue = "cloud";
  }

  get mode(): string {
    return this.modeValue;
  }

  async call(request: CallRequest | Record<string, unknown> | NormalizedCallRequest): Promise<CallResult> {
    const normalized = normalizeRequest(request);

    if (normalized.environment !== undefined && this.transport instanceof LocalHelperTransport) {
      const active = this.transport.activeEnvironment(normalized.path);
      if (active !== normalized.environment) {
        throw new InvalidRequest(
          `requested environment ${JSON.stringify(normalized.environment)} but the active CLI ` +
            `environment is ${JSON.stringify(active)}`,
        );
      }
    }

    const result = await this.transport.call(normalized);
    if (normalized.environment !== undefined && result.environment === undefined) {
      return { ...result, environment: normalized.environment };
    }
    return result;
  }

  async toolCall(args: Record<string, unknown>): Promise<string> {
    return JSON.stringify(await this.call(args));
  }

  toolSchema(): ToolSchema {
    return toolSchema();
  }

  get schema(): ToolSchema {
    return TOOL_SCHEMA;
  }

  toString(): string {
    return `AgentSecretsClient(mode=${JSON.stringify(this.modeValue)})`;
  }
}
