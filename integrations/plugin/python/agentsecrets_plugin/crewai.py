"""CrewAI adapter. Install with ``agentsecrets-plugin[crewai]``."""

from __future__ import annotations

from typing import Any, Dict, Optional, Type

from .schema import TOOL_DESCRIPTION, TOOL_NAME


def make_tool(client: Any, *, name: str = TOOL_NAME, description: str = TOOL_DESCRIPTION) -> Any:
    try:
        from crewai.tools import BaseTool
        from pydantic import BaseModel, ConfigDict, Field
    except ImportError as exc:  # pragma: no cover - depends on extras
        raise ImportError(
            "CrewAI support is not installed. Run: pip install 'agentsecrets-plugin[crewai]'"
        ) from exc

    class AgentSecretsInput(BaseModel):
        model_config = ConfigDict(extra="forbid")

        url: str
        injections: Dict[str, str]
        method: str = "GET"
        headers: Optional[Dict[str, str]] = None
        body: Optional[str] = None
        environment: Optional[str] = None
        path: Optional[str] = None
        agent_id: Optional[str] = None

    class AgentSecretsTool(BaseTool):
        name: str = name
        description: str = description
        args_schema: Type[BaseModel] = AgentSecretsInput
        client: Any = Field(exclude=True)

        def _run(self, **kwargs: Any) -> str:
            return self.client.tool_call(kwargs)

    return AgentSecretsTool(client=client)
