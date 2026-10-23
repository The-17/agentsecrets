"""Environment names accepted by the resolver.

The rule is the control plane's rule, kept identical on purpose: a name the
server would reject must fail here, before a request is built. Custom names are
as valid as the standard three. Whether a custom name may *resolve* is the
resolver's decision, never this plugin's.
"""

from __future__ import annotations

import re

from .errors import InvalidRequest

STANDARD_ENVIRONMENTS = ("development", "staging", "production")

RESERVED_ENVIRONMENTS = frozenset({"root", "admin", "api", "internal", "default"})

MAX_ENVIRONMENT_LENGTH = 32

NAME_PATTERN = r"^[a-z][a-z0-9-]{1,31}$"

NAME_RULE = (
    "lowercase letters, numbers and hyphens, starting with a letter, 2 to 32 characters"
)

_NAME = re.compile(NAME_PATTERN)


def parse_environment(value: str) -> str:
    """Normalize and validate an environment name, or raise InvalidRequest."""

    if not isinstance(value, str):
        raise InvalidRequest("environment must be a string")
    name = value.strip().lower()
    if not name:
        raise InvalidRequest(f"environment name is required: use {NAME_RULE}")
    if len(name) > MAX_ENVIRONMENT_LENGTH:
        raise InvalidRequest(
            f"environment name must be at most {MAX_ENVIRONMENT_LENGTH} characters"
        )
    if name in RESERVED_ENVIRONMENTS:
        raise InvalidRequest(f"{name!r} is a reserved environment name; choose another name")
    if not _NAME.match(name):
        raise InvalidRequest(f"invalid environment name {value!r}: use {NAME_RULE}")
    return name
