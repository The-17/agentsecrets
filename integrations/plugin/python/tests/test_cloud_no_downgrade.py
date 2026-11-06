"""A cloud failure must never fall back to local resolution.

Go pins this rule (``pkg/gateway/adversarial_test.go``): falling back to local
resolution during a cloud outage bypasses the resolver trust boundary and the
billing path. The plugins had no such pin, so a future "resilience" refactor
could add a silent local fallback and CI would stay green.
"""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from agentsecrets_plugin.client import AgentSecretsClient
from agentsecrets_plugin.errors import TransportError

REQUEST = {
    "url": "https://api.example.com/v1/things",
    "method": "GET",
    "injections": {"bearer": "STRIPE_KEY"},
}


class _FiveHundreds(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        self.send_response(503)
        self.end_headers()
        self.wfile.write(b"resolver down")

    def log_message(self, *args: object) -> None:  # silence test output
        return


class NoDowngradeTests(unittest.TestCase):
    def _sentinel_binary(self, directory: str) -> tuple[str, str]:
        """A CLI that records any invocation. Cloud mode must never run it.

        ``AGENTSECRETS_BINARY`` is pointed at it too, so mode resolution can
        find it exactly as it would in a real fallback.
        """
        marker = os.path.join(directory, "local-helper-ran")
        binary = os.path.join(directory, "agentsecrets")
        with open(binary, "w", encoding="utf-8") as handle:
            handle.write(f'#!/bin/sh\ntouch "{marker}"\nexit 0\n')
        os.chmod(binary, os.stat(binary).st_mode | stat.S_IEXEC)
        self.addCleanup(os.environ.pop, "AGENTSECRETS_BINARY", None)
        os.environ["AGENTSECRETS_BINARY"] = binary
        return binary, marker

    def test_unreachable_resolver_raises_and_never_downgrades(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary, marker = self._sentinel_binary(directory)
            client = AgentSecretsClient(
                mode="cloud",
                token="workload-token",
                binary=binary,
                resolver_url="http://127.0.0.1:1",
                timeout=2.0,
            )
            self.assertEqual(client.mode, "cloud")

            with self.assertRaises(TransportError):
                client.call(REQUEST)
            self.assertFalse(os.path.exists(marker), "cloud failure downgraded to the local helper")

    def test_resolver_5xx_raises_and_never_downgrades(self) -> None:
        server = HTTPServer(("127.0.0.1", 0), _FiveHundreds)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                binary, marker = self._sentinel_binary(directory)
                client = AgentSecretsClient(
                    mode="cloud",
                    token="workload-token",
                    binary=binary,
                    resolver_url=f"http://127.0.0.1:{server.server_port}",
                    timeout=2.0,
                )

                with self.assertRaises(TransportError):
                    client.call(REQUEST)
                self.assertFalse(os.path.exists(marker), "cloud failure downgraded to the local helper")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
