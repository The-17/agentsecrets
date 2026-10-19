"""Mode resolution and the child-process environment allowlist."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional

from .errors import ConfigurationError

DEFAULT_RESOLVER_URL = "https://resolver.agentsecrets.tech"
MODES = ("local", "cloud")

# Variables the helper may legitimately need. The cloud workload token and
# the use-cloud switch are deliberately absent.
CHILD_ENV_KEYS = (
    "PATH",
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "SystemRoot",
    "COMSPEC",
    "PATHEXT",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "AGENTSECRETS_ENV",
    "AGENTSECRETS_PROXY_PORT",
    "AGENTSECRETS_KEYCHAIN_CACHE_TTL_MS",
    "AGENTSECRETS_SERVER_URL",
    "AGENTSECRETS_API_URL",
    "AGENTSECRETS_STORAGE_MODE",
    "AS_AGENT_TOKEN",
    "AS_AGENT_TOKEN_FILE",
    "AGENTSECRETS_AGENT_TOKEN",
    "AGENTSECRETS_AGENT_TOKEN_FILE",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)

# Even if the caller passes an override, these never reach a child.
NEVER_FORWARD = (
    "AGENTSECRETS_TOKEN",
    "AGENTSECRETS_TOKEN_FILE",
    "AGENTSECRETS_USE_CLOUD",
    "AGENTSECRETS_SESSION_TOKEN",
    "AGENTSECRETS_PLUGIN_MODE",
    "AGENTSECRETS_BINARY",
    "AGENTSECRETS_CLOUD_RESOLVER_URL",
)


@dataclass(frozen=True)
class ModeConfig:
    mode: str
    binary: Optional[str] = None
    token: Optional[str] = None
    resolver_url: str = DEFAULT_RESOLVER_URL


def find_binary(explicit: Optional[str] = None) -> Optional[str]:
    candidate = (explicit or os.environ.get("AGENTSECRETS_BINARY") or "").strip()
    if candidate:
        path = Path(candidate).expanduser()
        if path.is_file():
            return str(path)
        found = shutil.which(candidate)
        if found:
            return found
        return None
    return shutil.which("agentsecrets")


def read_token(explicit: Optional[str] = None, token_file: Optional[str] = None) -> Optional[str]:
    token = (explicit or os.environ.get("AGENTSECRETS_TOKEN") or "").strip()
    if token:
        return token

    path_value = (token_file or os.environ.get("AGENTSECRETS_TOKEN_FILE") or "").strip()
    if not path_value:
        return None
    path = Path(path_value).expanduser()
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigurationError(f"cannot read AGENTSECRETS_TOKEN_FILE at {path}") from exc
    if not token:
        raise ConfigurationError(f"AGENTSECRETS_TOKEN_FILE at {path} is empty")
    return token


def resolve_mode(
    *,
    mode: Optional[str] = None,
    binary: Optional[str] = None,
    token: Optional[str] = None,
    token_file: Optional[str] = None,
    resolver_url: Optional[str] = None,
) -> ModeConfig:
    requested = (mode or os.environ.get("AGENTSECRETS_PLUGIN_MODE") or "").strip().lower()
    if requested and requested not in MODES:
        raise ConfigurationError(
            f"AGENTSECRETS_PLUGIN_MODE must be one of {', '.join(MODES)}; got {requested!r}"
        )

    found_binary = find_binary(binary)
    found_token = read_token(token, token_file)
    url = (resolver_url or os.environ.get("AGENTSECRETS_CLOUD_RESOLVER_URL") or DEFAULT_RESOLVER_URL).strip()

    if requested == "local":
        if not found_binary:
            raise ConfigurationError(
                "local mode was requested but no agentsecrets binary was found. "
                "Install the CLI or set AGENTSECRETS_BINARY."
            )
        return ModeConfig("local", binary=found_binary, resolver_url=url)

    if requested == "cloud":
        if not found_token:
            raise ConfigurationError(
                "cloud mode was requested but no workload token was found. "
                "Set AGENTSECRETS_TOKEN or AGENTSECRETS_TOKEN_FILE."
            )
        return ModeConfig("cloud", token=found_token, resolver_url=url)

    if found_binary:
        return ModeConfig("local", binary=found_binary, resolver_url=url)
    if found_token:
        return ModeConfig("cloud", token=found_token, resolver_url=url)

    raise ConfigurationError(
        "no AgentSecrets mode is available. Install the agentsecrets CLI for local mode, "
        "or set AGENTSECRETS_TOKEN or AGENTSECRETS_TOKEN_FILE for cloud mode."
    )


def build_child_env(overrides: Optional[Mapping[str, str]] = None) -> dict[str, str]:
    """Build the helper's environment from an allowlist.

    The parent environment is never forwarded wholesale. In particular the
    cloud workload token, the use-cloud switch, and the plugin's own mode
    variables are scrubbed even when a caller supplies an override.
    """

    env = {key: os.environ[key] for key in CHILD_ENV_KEYS if key in os.environ}
    if overrides:
        for key, value in overrides.items():
            if key in NEVER_FORWARD:
                continue
            env[str(key)] = str(value)
    for key in NEVER_FORWARD:
        env.pop(key, None)
    return env
