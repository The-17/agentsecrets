"""Local helper and cloud resolver transports."""

from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Mapping, Optional, Sequence

from .env import build_child_env
from .errors import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    InvalidRequest,
    QuotaExceededError,
    TransportError,
    UnsupportedInjection,
)
from .types import CallRequest, CallResult, parse_injections

_TOKEN_RE = re.compile(r"\bagt_[A-Za-z0-9._-]{8,}\b")


def _sanitize(text: str, token: Optional[str] = None) -> str:
    if token:
        text = text.replace(token, "[REDACTED]")
    return _TOKEN_RE.sub("[REDACTED]", text)


def _join_headers(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    out: dict[str, str] = {}
    for key, raw in value.items():
        if isinstance(raw, (list, tuple)):
            out[str(key)] = ", ".join(str(item) for item in raw)
        else:
            out[str(key)] = str(raw)
    return out


class LocalHelperTransport:
    """Call ``agentsecrets mcp bridge`` with JSON on stdin."""

    def __init__(
        self,
        binary: str,
        *,
        args: Sequence[str] = ("mcp", "bridge", "proxy.call"),
        status_args: Sequence[str] = ("mcp", "bridge", "status"),
        timeout: float = 60.0,
        cwd: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
        environment_ttl: float = 60.0,
    ) -> None:
        self._binary = binary
        self._args = tuple(args)
        self._status_args = tuple(status_args)
        self._timeout = timeout
        self._cwd = cwd
        self._env = dict(env or {})
        self._environment_ttl = environment_ttl
        self._environment_cache: dict[str, tuple[float, str]] = {}

    def _run(
        self,
        argv: Sequence[str],
        payload: str,
        timeout: float,
        cwd: Optional[str],
    ) -> Mapping[str, Any]:
        try:
            completed = subprocess.run(
                list(argv),
                input=payload,
                text=True,
                capture_output=True,
                timeout=timeout,
                cwd=cwd,
                env=build_child_env(self._env),
                check=False,
            )
        except FileNotFoundError as exc:
            raise ConfigurationError(f"agentsecrets binary not found at {self._binary}") from exc
        except subprocess.TimeoutExpired as exc:
            raise TransportError("agentsecrets helper timed out") from exc

        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()
        token = self._env.get("AGENTSECRETS_TOKEN")
        if completed.returncode != 0 and not stdout:
            raise TransportError(
                _sanitize(
                    f"agentsecrets helper exited {completed.returncode}: {stderr[-500:]}",
                    token,
                )
            )

        try:
            envelope = json.loads(stdout or "{}")
        except json.JSONDecodeError as exc:
            raise TransportError(
                _sanitize(
                    f"agentsecrets helper returned non-JSON stdout: {stderr[-300:]}",
                    token,
                )
            ) from exc

        if not isinstance(envelope, Mapping) or not isinstance(envelope.get("ok"), bool):
            raise TransportError("agentsecrets helper returned a malformed envelope")
        if not envelope["ok"]:
            message = envelope.get("error")
            raise TransportError(_sanitize(str(message or "agentsecrets helper failed"), token))

        data = envelope.get("data")
        if not isinstance(data, Mapping):
            raise TransportError("agentsecrets helper returned no data")
        return data

    def call(self, request: CallRequest) -> CallResult:
        prepared = request.prepared()
        data = self._run(
            [self._binary, *self._args],
            json.dumps(prepared.local_payload()),
            self._timeout,
            prepared.path or self._cwd,
        )
        try:
            status_code = int(data["status_code"])
            body = str(data["body"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TransportError("agentsecrets helper returned an invalid result") from exc

        environment = data.get("environment")
        return CallResult(
            status_code=status_code,
            headers=_join_headers(data.get("headers")),
            body=body,
            environment=str(environment) if environment else None,
        )

    def active_environment(self, *, cwd: Optional[str] = None) -> str:
        """Return the helper's active environment, cached briefly.

        The check runs before a call that names an environment. It reads the
        helper's own resolved environment, which is the same config the
        transient proxy uses.
        """

        effective_cwd = cwd or self._cwd
        cache_key = effective_cwd or ""
        now = time.monotonic()
        cached = self._environment_cache.get(cache_key)
        if cached is not None and now - cached[0] < self._environment_ttl:
            return cached[1]

        data = self._run(
            [self._binary, *self._status_args],
            "{}",
            min(self._timeout, 15.0),
            effective_cwd,
        )
        environment = data.get("environment")
        if not isinstance(environment, Mapping) or not isinstance(environment.get("active"), str):
            raise TransportError(
                "agentsecrets helper does not report its active environment. Upgrade the CLI."
            )
        active = str(environment["active"])
        self._environment_cache[cache_key] = (now, active)
        return active


class CloudResolverTransport:
    """Send one handle-substitution request to the cloud resolver."""

    def __init__(
        self,
        token: str,
        *,
        resolver_url: str = "https://resolver.agentsecrets.tech",
        timeout: float = 60.0,
        opener: Optional[Callable[..., Any]] = None,
    ) -> None:
        self._token = token
        self._resolver_url = resolver_url.rstrip("/")
        self._timeout = timeout
        self._opener = opener or urllib.request.urlopen

    def call(self, request: CallRequest) -> CallResult:
        payload = build_resolve_payload(request)
        data = json.dumps(payload).encode("utf-8")
        http_request = urllib.request.Request(
            self._resolver_url + "/v1/resolve",
            data=data,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
        )
        try:
            response = self._opener(http_request, timeout=self._timeout)
            try:
                raw = response.read()
            finally:
                close = getattr(response, "close", None)
                if callable(close):
                    close()
        except urllib.error.HTTPError as exc:
            status = exc.code
            detail = _sanitize(_read_error(exc), self._token)
            if status == 401:
                raise AuthenticationError("cloud resolver rejected the workload token") from exc
            if status == 403:
                raise AuthorizationError(detail or "cloud resolver denied the request") from exc
            if status == 429:
                raise QuotaExceededError(detail or "cloud resolver quota exceeded") from exc
            raise TransportError(detail or f"cloud resolver returned HTTP {status}") from exc
        except urllib.error.URLError as exc:
            raise TransportError(f"cloud resolver unreachable: {_sanitize(str(exc.reason), self._token)}") from exc

        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TransportError("cloud resolver returned non-JSON") from exc
        if not isinstance(decoded, Mapping):
            raise TransportError("cloud resolver returned an invalid result")

        try:
            status_code = int(decoded["status_code"])
            body = str(decoded["body"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TransportError("cloud resolver result is missing status_code or body") from exc

        redacted = decoded.get("redacted")
        return CallResult(
            status_code=status_code,
            headers=_join_headers(decoded.get("headers")),
            body=body,
            environment=request.environment,
            redacted=bool(redacted) if redacted is not None else None,
        )


def build_resolve_payload(request: CallRequest) -> dict[str, Any]:
    """Translate a call request into the resolver contract.

    Cloud mode substitutes ``{{KEY}}`` handles. It cannot base64-encode a
    basic credential or place one in a query parameter, so those styles fail
    before a request is made.
    """

    parsed_url = urllib.parse.urlparse(request.url)
    if parsed_url.scheme != "https":
        raise InvalidRequest("cloud mode requires an https:// target URL")

    prepared = request.prepared()
    headers = dict(prepared.headers)
    body = prepared.body or ""

    for injection in parse_injections(prepared.injections):
        handle = "{{" + injection.key + "}}"
        if injection.style == "bearer":
            headers["Authorization"] = "Bearer " + handle
        elif injection.style == "header":
            headers[injection.target] = handle
        elif injection.style == "body":
            try:
                parsed_body = json.loads(body) if body else {}
            except json.JSONDecodeError as exc:
                raise InvalidRequest("body injection requires a JSON object body") from exc
            if not isinstance(parsed_body, dict):
                raise InvalidRequest("body injection requires a JSON object body")
            _set_path(parsed_body, injection.target, handle)
            body = json.dumps(parsed_body, separators=(",", ":"))
            if not _has_header(headers, "Content-Type"):
                headers["Content-Type"] = "application/json"
        elif injection.style == "form":
            params = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
            params[injection.target] = handle
            body = urllib.parse.urlencode(params)
            if not _has_header(headers, "Content-Type"):
                headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            raise UnsupportedInjection(
                f"{injection.style} injection is not expressible in cloud mode. "
                "Use local mode, which has the CLI and keychain."
            )

    payload: dict[str, Any] = {
        "target_url": request.url,
        "method": request.method,
        "headers": headers,
        "body": body,
    }
    scope: dict[str, str] = {}
    if request.scope:
        scope.update(request.scope.to_wire())
    if request.environment:
        scope["environment"] = request.environment
    if scope:
        payload["scope"] = scope
    return payload


def _has_header(headers: Mapping[str, str], name: str) -> bool:
    wanted = name.lower()
    return any(str(key).lower() == wanted for key in headers)


def _set_path(obj: dict[str, Any], dotted: str, value: str) -> None:
    parts = [part for part in dotted.split(".") if part]
    if not parts:
        raise InvalidRequest("body injection requires a non-empty JSON path")
    cursor = obj
    for part in parts[:-1]:
        current = cursor.get(part)
        if not isinstance(current, dict):
            current = {}
            cursor[part] = current
        cursor = current
    cursor[parts[-1]] = value


def _read_error(exc: urllib.error.HTTPError) -> str:
    try:
        raw = exc.read().decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover - defensive
        return ""
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        return raw[:500]
    if isinstance(decoded, Mapping):
        for key in ("error", "message", "detail"):
            value = decoded.get(key)
            if isinstance(value, str) and value:
                return value[:500]
    return raw[:500]
