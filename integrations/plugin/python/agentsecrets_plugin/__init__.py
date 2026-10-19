"""AgentSecrets plugin for AI agent frameworks.

One tool, ``agentsecrets_call``, proxies an HTTP request using secret key
names. Values never cross the tool boundary.

Local mode delegates to the installed ``agentsecrets`` CLI helper. Cloud mode
calls the AgentSecrets resolver with ``{{KEY}}`` handles.
"""

from __future__ import annotations

from .client import AgentSecretsClient
from .errors import (
    AgentSecretsError,
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    InvalidRequest,
    QuotaExceededError,
    TransportError,
    UnsupportedInjection,
)
from .schema import TOOL_DESCRIPTION, TOOL_NAME, TOOL_PARAMETERS, TOOL_SCHEMA, tool_schema
from .types import CallRequest, CallResult, Injection, Scope, parse_injections

__all__ = [
    "AgentSecretsClient",
    "AgentSecretsError",
    "AuthenticationError",
    "AuthorizationError",
    "CallRequest",
    "CallResult",
    "ConfigurationError",
    "Injection",
    "InvalidRequest",
    "QuotaExceededError",
    "Scope",
    "TOOL_DESCRIPTION",
    "TOOL_NAME",
    "TOOL_PARAMETERS",
    "TOOL_SCHEMA",
    "TransportError",
    "UnsupportedInjection",
    "parse_injections",
    "tool_schema",
]
