"""The AgentSecrets plugin client."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, Mapping, Optional

from .env import resolve_mode
from .errors import InvalidRequest
from .schema import TOOL_SCHEMA, tool_schema
from .transports import CloudResolverTransport, LocalHelperTransport
from .types import CallRequest, CallResult


class AgentSecretsClient:
    """One operation: proxy an HTTP request with secret key names."""

    def __init__(
        self,
        *,
        mode: Optional[str] = None,
        binary: Optional[str] = None,
        token: Optional[str] = None,
        token_file: Optional[str] = None,
        resolver_url: Optional[str] = None,
        timeout: float = 60.0,
        transport: Optional[Any] = None,
    ) -> None:
        self._mode = "custom"
        if transport is not None:
            self._transport = transport
            return

        config = resolve_mode(
            mode=mode,
            binary=binary,
            token=token,
            token_file=token_file,
            resolver_url=resolver_url,
        )
        self._mode = config.mode
        if config.mode == "local":
            self._transport = LocalHelperTransport(config.binary or "", timeout=timeout)
        else:
            self._transport = CloudResolverTransport(
                config.token or "",
                resolver_url=config.resolver_url,
                timeout=timeout,
            )

    @property
    def mode(self) -> str:
        return self._mode

    def call(self, request: CallRequest | Mapping[str, Any]) -> CallResult:
        if isinstance(request, Mapping):
            request = CallRequest.from_mapping(request)

        checker = getattr(self._transport, "active_environment", None)
        if request.environment and callable(checker):
            active = checker(cwd=request.path)
            if active != request.environment:
                raise InvalidRequest(
                    f"requested environment {request.environment!r} but the active CLI "
                    f"environment is {active!r}"
                )

        result = self._transport.call(request)
        if request.environment and result.environment is None:
            result = replace(result, environment=request.environment)
        return result

    def tool_call(self, args: Mapping[str, Any]) -> str:
        """Return the tool result as a compact JSON string."""

        return json.dumps(self.call(args).to_dict(), separators=(",", ":"))

    @staticmethod
    def tool_schema() -> dict:
        return tool_schema()

    @property
    def schema(self) -> dict:
        return TOOL_SCHEMA

    def __repr__(self) -> str:
        return f"AgentSecretsClient(mode={self._mode!r})"
