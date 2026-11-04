"""Client-side SSRF guard for the cloud resolver transport.

The resolver has one fixed origin. Following a 3xx would resend the workload
token to a host that never proved it owns the credential, so a redirect is a
protocol error and the call fails closed.
"""

from __future__ import annotations

import http.server
import threading
import unittest

from agentsecrets_plugin import CallRequest
from agentsecrets_plugin.errors import TransportError
from agentsecrets_plugin.transports import CloudResolverTransport


class _Counter:
    def __init__(self) -> None:
        self.hits = 0


class _CanaryHandler(http.server.BaseHTTPRequestHandler):
    hits = _Counter()

    def _respond(self) -> None:
        type(self).hits.hits += 1
        body = b'{"status_code": 200, "headers": {}, "body": "pwned"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        self._respond()

    # urllib rewrites a redirected POST to GET, so both verbs must be served.
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        self._respond()

    def log_message(self, *args: object) -> None:
        pass


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    canary_url = ""

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        self.send_response(302)
        self.send_header("Location", type(self).canary_url + "/v1/resolve")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


def _serve(handler: type[http.server.BaseHTTPRequestHandler]) -> tuple[http.server.HTTPServer, str]:
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    return server, f"http://{host}:{port}"


class CloudResolverRedirectTest(unittest.TestCase):
    def test_does_not_follow_resolver_redirect(self) -> None:
        _CanaryHandler.hits = _Counter()
        canary_server, canary_url = _serve(_CanaryHandler)
        _RedirectHandler.canary_url = canary_url
        resolver_server, resolver_url = _serve(_RedirectHandler)
        try:
            transport = CloudResolverTransport(token="workload-token", resolver_url=resolver_url, timeout=5.0)
            with self.assertRaises(TransportError):
                transport.call(CallRequest(url="https://api.example.com", injections={"bearer": "KEY"}))
            self.assertEqual(
                _CanaryHandler.hits.hits,
                0,
                "transport followed the resolver redirect and hit the redirect target",
            )
        finally:
            resolver_server.shutdown()
            canary_server.shutdown()
            resolver_server.server_close()
            canary_server.server_close()


if __name__ == "__main__":
    unittest.main()
