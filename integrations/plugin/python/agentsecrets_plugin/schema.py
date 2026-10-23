"""Tool schema for agentsecrets_call."""

from __future__ import annotations

import copy

from .environment import NAME_PATTERN, NAME_RULE, STANDARD_ENVIRONMENTS

TOOL_NAME = "agentsecrets_call"
TOOL_DESCRIPTION = (
    "Call an HTTPS API with AgentSecrets-injected credentials. "
    "Pass secret KEY NAMES only. Values never enter the model or this tool."
)

TOOL_SCHEMA = {
    "name": TOOL_NAME,
    "description": TOOL_DESCRIPTION,
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "required": ["url", "injections"],
        "properties": {
            "url": {"type": "string", "description": "Target HTTPS URL."},
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                "default": "GET",
            },
            "injections": {
                "type": "object",
                "description": (
                    "Map of injection spec to secret KEY NAME. Specs: bearer, basic, "
                    "header:Name, query:param, body:json.path, form:field. Never pass a value."
                ),
                "additionalProperties": {"type": "string"},
                "minProperties": 1,
            },
            "headers": {
                "type": "object",
                "description": "Extra non-credential request headers.",
                "additionalProperties": {"type": "string"},
            },
            "body": {
                "type": "string",
                "description": "Request body as a string. Use JSON for body: and form: injections.",
            },
            "environment": {
                "type": "string",
                "pattern": NAME_PATTERN,
                "description": (
                    "Asserts the expected environment: "
                    + NAME_RULE
                    + ". Standard names are "
                    + ", ".join(STANDARD_ENVIRONMENTS)
                    + "; other valid names are custom and resolve on Pro plans only. "
                    "Cloud checks the token binding; local checks the active CLI environment."
                ),
            },
            "path": {
                "type": "string",
                "description": "Local project directory. Defaults to the process working directory.",
            },
            "agent_id": {
                "type": "string",
                "description": "Agent name for audit attribution. Defaults to plugin.",
            },
        },
    },
}

TOOL_PARAMETERS = TOOL_SCHEMA["parameters"]


def tool_schema() -> dict:
    """Return a defensive copy of the tool schema."""

    return copy.deepcopy(TOOL_SCHEMA)
