"""AutoGen adapter. Install with ``agentsecrets-plugin[autogen]``."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .schema import TOOL_DESCRIPTION, TOOL_NAME


def make_tool(client: Any, *, name: str = TOOL_NAME, description: str = TOOL_DESCRIPTION) -> Any:
    try:
        from autogen_core.tools import FunctionTool
    except ImportError as exc:  # pragma: no cover - depends on extras
        raise ImportError(
            "AutoGen support is not installed. Run: pip install 'agentsecrets-plugin[autogen]'"
        ) from exc

    async def agentsecrets_call(
        url: str,
        injections: Dict[str, str],
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        environment: Optional[str] = None,
        path: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> str:
        return client.tool_call(
            {
                "url": url,
                "injections": injections,
                "method": method,
                "headers": headers,
                "body": body,
                "environment": environment,
                "path": path,
                "agent_id": agent_id,
            }
        )

    return FunctionTool(agentsecrets_call, name=name, description=description)
