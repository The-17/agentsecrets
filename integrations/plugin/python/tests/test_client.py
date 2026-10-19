from __future__ import annotations

import json
import unittest

from agentsecrets_plugin import AgentSecretsClient, CallRequest, CallResult, TOOL_SCHEMA


class StubTransport:
    def __init__(self) -> None:
        self.requests = []

    def call(self, request: CallRequest) -> CallResult:
        self.requests.append(request)
        return CallResult(
            status_code=200,
            headers={"content-type": "application/json"},
            body='{"ok":true}',
            environment=request.environment,
        )


class ClientTests(unittest.TestCase):
    def test_call_accepts_mapping_and_tool_call_returns_json(self) -> None:
        transport = StubTransport()
        client = AgentSecretsClient(transport=transport)

        output = client.tool_call(
            {
                "url": "https://api.example.com",
                "injections": {"bearer": "KEY"},
                "environment": "staging",
            }
        )

        self.assertEqual(client.mode, "custom")
        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(transport.requests[0].agent_id, "plugin")
        self.assertEqual(
            json.loads(output),
            {
                "status_code": 200,
                "headers": {"content-type": "application/json"},
                "body": '{"ok":true}',
                "environment": "staging",
            },
        )

    def test_schema_is_the_shared_contract(self) -> None:
        client = AgentSecretsClient(transport=StubTransport())
        self.assertEqual(client.tool_schema(), TOOL_SCHEMA)
        self.assertEqual(client.schema["name"], "agentsecrets_call")

    def test_repr_does_not_include_a_token(self) -> None:
        client = AgentSecretsClient(transport=StubTransport())
        self.assertNotIn("token", repr(client).lower())


if __name__ == "__main__":
    unittest.main()
