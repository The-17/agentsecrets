export class AgentSecretsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class ConfigurationError extends AgentSecretsError {}

export class InvalidRequest extends AgentSecretsError {}

export class TransportError extends AgentSecretsError {}

export class AuthenticationError extends TransportError {}

export class AuthorizationError extends TransportError {}

export class QuotaExceededError extends TransportError {}

export class UnsupportedInjection extends InvalidRequest {}
