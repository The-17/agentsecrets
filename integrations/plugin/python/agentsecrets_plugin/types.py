"""Request and result types for the AgentSecrets plugin."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from .errors import InvalidRequest
from .environment import parse_environment

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
TARGETED_STYLES = ("header", "query", "body", "form")
UNTARGETED_STYLES = ("bearer", "basic")


@dataclass(frozen=True)
class Injection:
    style: str
    target: str
    key: str


def parse_injections(raw: Mapping[str, str]) -> tuple[Injection, ...]:
    """Parse the wire map into validated injections.

    The map goes from injection spec to secret KEY NAME. Values are never
    accepted here, and the key name is not read from the environment.
    """

    if not raw:
        raise InvalidRequest("injections must contain at least one entry")

    parsed: list[Injection] = []
    for spec, key in raw.items():
        if not isinstance(spec, str) or not isinstance(key, str):
            raise InvalidRequest("injections must map string specs to string key names")
        if not key.strip():
            raise InvalidRequest("injection key name must not be empty")
        if key != key.strip():
            raise InvalidRequest("injection key name must not contain surrounding whitespace")

        style, sep, target = spec.partition(":")
        style = style.strip().lower()
        target = target.strip()

        if style in UNTARGETED_STYLES:
            if sep:
                raise InvalidRequest(f"{style} injection does not take a target")
        elif style in TARGETED_STYLES:
            if not target:
                raise InvalidRequest(f"{style} injection requires a target, for example {style}:name")
        else:
            raise InvalidRequest(
                "unknown injection style {!r}. Valid styles: bearer, basic, "
                "header:name, query:param, body:path, form:field".format(spec)
            )

        parsed.append(Injection(style=style, target=target, key=key))

    return tuple(parsed)


@dataclass(frozen=True)
class Scope:
    workspace_id: Optional[str] = None
    project_id: Optional[str] = None

    def to_wire(self) -> dict[str, str]:
        out: dict[str, str] = {}
        if self.workspace_id:
            out["workspace_id"] = self.workspace_id
        if self.project_id:
            out["project_id"] = self.project_id
        return out


@dataclass(frozen=True)
class CallRequest:
    url: str
    injections: Mapping[str, str]
    method: str = "GET"
    headers: Mapping[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    environment: Optional[str] = None
    path: Optional[str] = None
    agent_id: str = "plugin"
    scope: Optional[Scope] = None

    def __post_init__(self) -> None:
        if not isinstance(self.url, str) or not self.url.strip():
            raise InvalidRequest("url is required")
        if not isinstance(self.method, str):
            raise InvalidRequest("method must be a string")
        method = self.method.upper()
        if method not in METHODS:
            raise InvalidRequest("method must be one of " + ", ".join(METHODS))
        object.__setattr__(self, "method", method)

        if not isinstance(self.injections, Mapping):
            raise InvalidRequest("injections must be an object")
        if not isinstance(self.headers, Mapping):
            raise InvalidRequest("headers must be an object")
        if self.body is not None and not isinstance(self.body, str):
            raise InvalidRequest("body must be a string")
        if self.path is not None and not isinstance(self.path, str):
            raise InvalidRequest("path must be a string")
        if self.scope is not None and not isinstance(self.scope, Scope):
            raise InvalidRequest("scope must be a Scope")
        if not isinstance(self.agent_id, str) or not self.agent_id.strip():
            raise InvalidRequest("agent_id must be a non-empty string")

        normalized: dict[str, str] = {}
        for key, raw in self.headers.items():
            if not isinstance(key, str) or not isinstance(raw, str):
                raise InvalidRequest("headers must map string names to string values")
            normalized[key] = raw
        object.__setattr__(self, "headers", normalized)

        if self.environment is not None:
            object.__setattr__(self, "environment", parse_environment(self.environment))

        parsed = parse_injections(dict(self.injections))
        object.__setattr__(
            self,
            "injections",
            {i.style + (":" + i.target if i.target else ""): i.key for i in parsed},
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CallRequest":
        scope_value = value.get("scope")
        scope = None
        if isinstance(scope_value, Mapping):
            scope = Scope(
                workspace_id=_optional_str(scope_value.get("workspace_id") or scope_value.get("workspaceId")),
                project_id=_optional_str(scope_value.get("project_id") or scope_value.get("projectId")),
            )
        headers = value.get("headers") or {}
        if not isinstance(headers, Mapping):
            raise InvalidRequest("headers must be an object")
        injections = value.get("injections")
        if not isinstance(injections, Mapping):
            raise InvalidRequest("injections must be an object")
        body_value = value.get("body")
        if body_value is not None and not isinstance(body_value, str):
            raise InvalidRequest("body must be a string")
        agent_value = value.get("agent_id") or value.get("agentId") or "plugin"
        return cls(
            url=value.get("url") if isinstance(value.get("url"), str) else "",
            injections=dict(injections),
            method=value.get("method") if isinstance(value.get("method"), str) else "GET",
            headers=dict(headers),
            body=body_value,
            environment=_optional_str(value.get("environment")),
            path=_optional_str(value.get("path")),
            agent_id=str(agent_value),
            scope=scope,
        )

    def prepared(self) -> "CallRequest":
        """Return a copy with a JSON Content-Type when the body is JSON.

        The installed CLI may predate the engine fix that does this. Setting
        it at the plugin boundary keeps JSON targets working either way.
        """

        headers = dict(self.headers)
        if self.body and not any(k.lower() == "content-type" for k in headers):
            try:
                json.loads(self.body)
            except (TypeError, ValueError):
                pass
            else:
                headers["Content-Type"] = "application/json"
        if headers == dict(self.headers):
            return self
        return CallRequest(
            url=self.url,
            injections=self.injections,
            method=self.method,
            headers=headers,
            body=self.body,
            environment=self.environment,
            path=self.path,
            agent_id=self.agent_id,
            scope=self.scope,
        )

    def local_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "url": self.url,
            "method": self.method,
            "injections": dict(self.injections),
            "agent_id": self.agent_id,
        }
        if self.headers:
            payload["headers"] = dict(self.headers)
        if self.body is not None:
            payload["body"] = self.body
        if self.environment:
            payload["environment"] = self.environment
        if self.path:
            payload["path"] = self.path
        return payload


@dataclass(frozen=True)
class CallResult:
    status_code: int
    headers: Mapping[str, str]
    body: str
    environment: Optional[str] = None
    redacted: Optional[bool] = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "status_code": self.status_code,
            "headers": dict(self.headers),
            "body": self.body,
        }
        if self.environment:
            out["environment"] = self.environment
        if self.redacted is not None:
            out["redacted"] = self.redacted
        return out


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
