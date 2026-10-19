from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentsecrets_plugin.env import (
    NEVER_FORWARD,
    build_child_env,
    find_binary,
    read_token,
    resolve_mode,
)
from agentsecrets_plugin.errors import ConfigurationError


class ChildEnvTests(unittest.TestCase):
    def test_allowlist_keeps_config_and_scrubs_cloud_token(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/usr/bin",
                "AGENTSECRETS_ENV": "staging",
                "AGENTSECRETS_PROXY_PORT": "8787",
                "AS_AGENT_TOKEN": "agent-token",
                "AGENTSECRETS_TOKEN": "workload-token",
                "AGENTSECRETS_TOKEN_FILE": "/tmp/token",
                "AGENTSECRETS_USE_CLOUD": "1",
                "AGENTSECRETS_PLUGIN_MODE": "cloud",
                "AGENTSECRETS_BINARY": "/bin/agentsecrets",
                "AGENTSECRETS_CLOUD_RESOLVER_URL": "https://resolver.example",
                "UNRELATED_SECRET": "nope",
            },
            clear=True,
        ):
            env = build_child_env()
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertEqual(env["AGENTSECRETS_ENV"], "staging")
        self.assertEqual(env["AS_AGENT_TOKEN"], "agent-token")
        self.assertNotIn("UNRELATED_SECRET", env)
        for key in NEVER_FORWARD:
            self.assertNotIn(key, env)

    def test_overrides_cannot_reintroduce_never_forward_keys(self) -> None:
        env = build_child_env(
            {
                "AGENTSECRETS_TOKEN": "workload-token",
                "AGENTSECRETS_USE_CLOUD": "1",
                "CUSTOM": "value",
            }
        )
        self.assertNotIn("AGENTSECRETS_TOKEN", env)
        self.assertNotIn("AGENTSECRETS_USE_CLOUD", env)
        self.assertEqual(env["CUSTOM"], "value")


class ModeTests(unittest.TestCase):
    def test_explicit_local_without_binary_fails(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch(
            "agentsecrets_plugin.env.shutil.which", return_value=None
        ):
            with self.assertRaises(ConfigurationError):
                resolve_mode(mode="local")

    def test_explicit_cloud_without_token_fails(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch(
            "agentsecrets_plugin.env.shutil.which", return_value=None
        ):
            with self.assertRaises(ConfigurationError):
                resolve_mode(mode="cloud")

    def test_invalid_mode_fails(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch(
            "agentsecrets_plugin.env.shutil.which", return_value=None
        ):
            with self.assertRaises(ConfigurationError):
                resolve_mode(mode="sideways")

    def test_explicit_binary_resolves_local(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {}, clear=True):
            binary = Path(tmp) / "agentsecrets"
            binary.write_text("", encoding="utf-8")
            config = resolve_mode(binary=str(binary))
        self.assertEqual(config.mode, "local")
        self.assertEqual(config.binary, str(binary))

    def test_token_resolves_cloud_when_no_binary(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch(
            "agentsecrets_plugin.env.shutil.which", return_value=None
        ):
            config = resolve_mode(token="workload-token")
        self.assertEqual(config.mode, "cloud")
        self.assertEqual(config.token, "workload-token")

    def test_auto_prefers_local_over_cloud(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {}, clear=True):
            binary = Path(tmp) / "agentsecrets"
            binary.write_text("", encoding="utf-8")
            config = resolve_mode(binary=str(binary), token="workload-token")
        self.assertEqual(config.mode, "local")

    def test_token_file_is_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {}, clear=True):
            token_file = Path(tmp) / "token"
            token_file.write_text("file-token\n", encoding="utf-8")
            self.assertEqual(read_token(token_file=str(token_file)), "file-token")
            config = resolve_mode(token_file=str(token_file))
        self.assertEqual(config.mode, "cloud")
        self.assertEqual(config.token, "file-token")

    def test_missing_token_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ConfigurationError):
                read_token(token_file=str(Path(tmp) / "missing"))

    def test_find_binary_returns_none_for_missing_explicit_path(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(find_binary("/no/such/agentsecrets"))


if __name__ == "__main__":
    unittest.main()
