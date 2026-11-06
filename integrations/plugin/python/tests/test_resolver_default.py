import unittest
from pathlib import Path

from agentsecrets_plugin.env import DEFAULT_RESOLVER_URL
from agentsecrets_plugin.transports import CloudResolverTransport

_TRANSPORTS_SOURCE = (
    Path(__file__).resolve().parent.parent / "agentsecrets_plugin" / "transports.py"
)


class ResolverDefaultTests(unittest.TestCase):
    """The transport default must be the single guarded resolver constant.

    `env.DEFAULT_RESOLVER_URL` is the one source of the resolver host and the
    one `test_env` already pins. Every cloud call goes through the transport,
    so its own default has to be that same constant. A literal here was a
    second source, and a host change in env.py would have left this transport
    silently talking to the old host. A value-only assertion cannot catch that,
    because a stale literal has the same value as the constant today, so the
    guard is on the source: no bare host in the file.
    """

    def test_transport_source_has_no_bare_resolver_host(self) -> None:
        source = _TRANSPORTS_SOURCE.read_text(encoding="utf-8")
        self.assertNotIn(
            "https://resolver.",
            source,
            "transports.py holds its own resolver host: use DEFAULT_RESOLVER_URL",
        )

    def test_transport_defaults_to_the_guarded_constant(self) -> None:
        transport = CloudResolverTransport("workload-token")
        self.assertEqual(transport._resolver_url, DEFAULT_RESOLVER_URL)

    def test_explicit_url_still_overrides(self) -> None:
        transport = CloudResolverTransport("workload-token", resolver_url="https://resolver.example/")
        self.assertEqual(transport._resolver_url, "https://resolver.example")


if __name__ == "__main__":
    unittest.main()
