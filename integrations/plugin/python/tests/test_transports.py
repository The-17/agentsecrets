from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from agentsecrets_plugin import AgentSecretsClient, CallRequest, InvalidRequest, UnsupportedInjection
from agentsecrets_plugin.errors import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    QuotaExceededError,
    TransportError,
)
from agentsecrets_plugin.transports import (
    CloudResolverTransport,
    LocalHelperTransport,
    build_resolve_payload,
)

HELPER = """\
import json
import os
import sys

if sys.argv[1:] == ["mcp", "bridge", "status"]:
    print(json.dumps({"ok": True, "data": {"environment": {"active": "staging", "source": "test"}}}))
    raise SystemExit(0)

payload = json.load(sys.stdin)
body = {
    "injections": payload.get("injections"),
    "headers": payload.get("headers"),
    "agent_id": payload.get("agent_id"),
    "environment": payload.get("environment"),
    "cloud_token": os.environ.get("AGENTSECRETS_TOKEN", "MISSING"),
    "use_cloud": os.environ.get("AGENTSECRETS_USE_CLOUD", "MISSING"),
    "agent_token": os.environ.get("AS_AGENT_TOKEN", "MISSING"),
}
print(json.dumps({
    "ok": True,
    "data": {
        "status_code": 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body),
        "environment": payload.get("environment"),
    },
}))
"""

MISMATCH_HELPER = """\
import json
import sys

marker = {marker!r}
if sys.argv[1:] == ["mcp", "bridge", "status"]:
    print(json.dumps({{"ok": True, "data": {{"environment": {{"active": "staging"}}}}}}))
    raise SystemExit(0)

with open(marker, "a", encoding="utf-8") as handle:
    handle.write("called\\n")
print(json.dumps({{"ok": True, "data": {{"status_code": 200, "headers": {{}}, "body": "ok"}}}}))
"""

ERROR_HELPER = """\
import json
print(json.dumps({"ok": False, "error": "boom"}))
"""

MALFORMED_HELPER = """\
print("not-json")
"""

SLEEP_HELPER = """\
import time
time.sleep(5)
"""


class LocalHelperTransportTests(unittest.TestCase):
    def helper(self, source: str) -> LocalHelperTransport:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        script = Path(self._tmp.name) / "helper.py"
        script.write_text(source, encoding="utf-8")
        return LocalHelperTransport(
            sys.executable,
            args=(str(script),),
            status_args=(str(script), "mcp", "bridge", "status"),
            timeout=2,
        )

    def test_active_environment_uses_status(self) -> None:
        transport = self.helper(HELPER)
        self.assertEqual(transport.active_environment(), "staging")

    def test_environment_mismatch_fails_before_proxy_call(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        marker = Path(self._tmp.name) / "called.txt"
        script = Path(self._tmp.name) / "helper.py"
        script.write_text(MISMATCH_HELPER.format(marker=str(marker)), encoding="utf-8")
        transport = LocalHelperTransport(
            sys.executable,
            args=(str(script),),
            status_args=(str(script), "mcp", "bridge", "status"),
            timeout=2,
        )
        client = AgentSecretsClient(transport=transport)

        with self.assertRaises(InvalidRequest):
            client.call(
                {
                    "url": "https://api.example.com",
                    "injections": {"bearer": "KEY"},
                    "environment": "production",
                }
            )
        self.assertFalse(marker.exists())

        result = client.call(
            {
                "url": "https://api.example.com",
                "injections": {"bearer": "KEY"},
                "environment": "staging",
            }
        )
        self.assertEqual(result.environment, "staging")
        self.assertTrue(marker.exists())

    def test_sends_key_names_and_scrubs_parent_secrets(self) -> None:
        transport = self.helper(HELPER)
        with mock.patch.dict(
            os.environ,
            {
                "AGENTSECRETS_TOKEN": "workload-secret",
                "AGENTSECRETS_USE_CLOUD": "1",
                "AS_AGENT_TOKEN": "agent-token",
                "AGENTSECRETS_ENV": "staging",
            },
            clear=False,
        ):
            result = transport.call(
                CallRequest(
                    url="https://api.example.com/v1/things",
                    injections={"bearer": "STRIPE_KEY"},
                    headers={"X-Trace": "abc"},
                    body='{"hello":"world"}',
                    environment="staging",
                    agent_id="test-agent",
                )
            )

        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.environment, "staging")
        self.assertEqual(result.headers["content-type"], "application/json")
        sent = json.loads(result.body)
        self.assertEqual(sent["injections"], {"bearer": "STRIPE_KEY"})
        self.assertEqual(sent["agent_id"], "test-agent")
        self.assertEqual(sent["environment"], "staging")
        self.assertEqual(sent["headers"]["Content-Type"], "application/json")
        self.assertEqual(sent["cloud_token"], "MISSING")
        self.assertEqual(sent["use_cloud"], "MISSING")
        self.assertEqual(sent["agent_token"], "agent-token")

    def test_surfaces_error_envelope(self) -> None:
        transport = self.helper(ERROR_HELPER)
        with self.assertRaises(TransportError) as ctx:
            transport.call(
                CallRequest(url="https://api.example.com", injections={"bearer": "KEY"})
            )
        self.assertIn("boom", str(ctx.exception))

    def test_surfaces_non_json_helper_output(self) -> None:
        transport = self.helper(MALFORMED_HELPER)
        with self.assertRaises(TransportError):
            transport.call(
                CallRequest(url="https://api.example.com", injections={"bearer": "KEY"})
            )

    def test_surfaces_timeout(self) -> None:
        transport = self.helper(SLEEP_HELPER)
        transport._timeout = 0.2
        with self.assertRaises(TransportError):
            transport.call(
                CallRequest(url="https://api.example.com", injections={"bearer": "KEY"})
            )

    def test_missing_binary_is_a_configuration_error(self) -> None:
        transport = LocalHelperTransport("/no/such/agentsecrets")
        with self.assertRaises(ConfigurationError):
            transport.call(
                CallRequest(url="https://api.example.com", injections={"bearer": "KEY"})
            )


class ResolvePayloadTests(unittest.TestCase):
    def test_bearer_header_and_json_body(self) -> None:
        request = CallRequest(
            url="https://api.example.com/v1/things",
            injections={
                "bearer": "A_KEY",
                "header:X-Tenant": "B_KEY",
                "body:auth.key": "C_KEY",
            },
            body='{"name":"example"}',
            environment="staging",
        )
        payload = build_resolve_payload(request)
        self.assertEqual(payload["target_url"], "https://api.example.com/v1/things")
        self.assertEqual(payload["headers"]["Authorization"], "Bearer {{A_KEY}}")
        self.assertEqual(payload["headers"]["X-Tenant"], "{{B_KEY}}")
        self.assertEqual(payload["headers"]["Content-Type"], "application/json")
        self.assertEqual(json.loads(payload["body"]), {"name": "example", "auth": {"key": "{{C_KEY}}"}})
        self.assertEqual(payload["scope"], {"environment": "staging"})

    def test_form_body(self) -> None:
        request = CallRequest(
            url="https://api.example.com/token",
            injections={"form:api_key": "KEY"},
            body="grant_type=client_credentials",
        )
        payload = build_resolve_payload(request)
        self.assertEqual(
            payload["body"],
            "grant_type=client_credentials&api_key=%7B%7BKEY%7D%7D",
        )
        self.assertEqual(payload["headers"]["Content-Type"], "application/x-www-form-urlencoded")

    def test_rejects_basic_and_query(self) -> None:
        for spec in ("basic", "query:api_key"):
            with self.subTest(spec=spec):
                with self.assertRaises(UnsupportedInjection):
                    build_resolve_payload(
                        CallRequest(
                            url="https://api.example.com",
                            injections={spec: "KEY"},
                        )
                    )

    def test_rejects_non_https(self) -> None:
        with self.assertRaises(InvalidRequest):
            build_resolve_payload(
                CallRequest(url="http://api.example.com", injections={"bearer": "KEY"})
            )

    def test_rejects_body_injection_on_non_object(self) -> None:
        with self.assertRaises(InvalidRequest):
            build_resolve_payload(
                CallRequest(
                    url="https://api.example.com",
                    injections={"body:key": "KEY"},
                    body="[]",
                )
            )


class CloudResolverTransportTests(unittest.TestCase):
    def test_posts_handles_with_bearer_auth(self) -> None:
        captured = {}

        class Response:
            def read(self) -> bytes:
                return json.dumps(
                    {
                        "status_code": 201,
                        "headers": {"x-request-id": "abc"},
                        "body": "created",
                        "redacted": True,
                    }
                ).encode("utf-8")

            def close(self) -> None:
                pass

        def opener(request, timeout):
            captured["url"] = request.full_url
            captured["method"] = request.get_method()
            captured["auth"] = request.get_header("Authorization")
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return Response()

        transport = CloudResolverTransport(
            "workload-token",
            resolver_url="https://resolver.example",
            timeout=12,
            opener=opener,
        )
        result = transport.call(
            CallRequest(
                url="https://api.example.com",
                injections={"bearer": "KEY"},
                environment="production",
            )
        )

        self.assertEqual(captured["url"], "https://resolver.example/v1/resolve")
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["auth"], "Bearer workload-token")
        self.assertEqual(captured["body"]["headers"]["Authorization"], "Bearer {{KEY}}")
        self.assertEqual(captured["body"]["scope"], {"environment": "production"})
        self.assertEqual(captured["timeout"], 12)
        self.assertEqual(result.status_code, 201)
        self.assertEqual(result.environment, "production")
        self.assertTrue(result.redacted)

    def test_maps_auth_errors(self) -> None:
        cases = [
            (401, AuthenticationError),
            (403, AuthorizationError),
            (429, QuotaExceededError),
        ]
        for status, error_type in cases:
            with self.subTest(status=status):
                def opener(request, timeout, status=status):
                    raise urllib.error.HTTPError(request.full_url, status, "nope", {}, None)

                transport = CloudResolverTransport("tok", opener=opener)
                with self.assertRaises(error_type):
                    transport.call(
                        CallRequest(url="https://api.example.com", injections={"bearer": "KEY"})
                    )


if __name__ == "__main__":
    unittest.main()
