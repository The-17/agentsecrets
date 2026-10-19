"""Error types for the AgentSecrets plugin."""

from __future__ import annotations


class AgentSecretsError(Exception):
    """Base error. Messages never contain secret values."""


class ConfigurationError(AgentSecretsError):
    """The client cannot resolve a usable mode, binary, token, or resolver URL."""


class InvalidRequest(AgentSecretsError):
    """The call request is malformed."""


class TransportError(AgentSecretsError):
    """The helper or resolver failed to complete the call."""


class AuthenticationError(TransportError):
    """The cloud resolver rejected the workload token."""


class AuthorizationError(TransportError):
    """The target, scope, or environment is not authorized."""


class QuotaExceededError(TransportError):
    """The resolver quota is exhausted."""


class UnsupportedInjection(InvalidRequest):
    """The selected transport cannot express this injection style."""
