import importlib.util
import os
import stat
import tempfile
import unittest
from unittest import mock

SOURCE = os.path.join(os.path.dirname(__file__), "..", "src", "agentsecrets", "binary.py")


def load_binary_module():
    spec = importlib.util.spec_from_file_location("agentsecrets_binary_under_test", SOURCE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_executable(path, body="#!/bin/sh\necho STUB\n"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


class BinaryResolutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.mod = load_binary_module()
        self.env_patch = mock.patch.dict(
            os.environ,
            {"AGENTSECRETS_BINARY": "", "AGENTSECRETS_HOME": "", "HOME": self.tmp.name},
            clear=False,
        )
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        os.environ.pop("AGENTSECRETS_BINARY", None)
        os.environ.pop("AGENTSECRETS_HOME", None)

    def test_explicit_override_wins_without_any_network_call(self):
        stub = make_executable(os.path.join(self.tmp.name, "custom", "agentsecrets"))
        os.environ["AGENTSECRETS_BINARY"] = stub
        with mock.patch.object(self.mod.urllib.request, "urlopen", side_effect=AssertionError("network call")) as net, \
             mock.patch.object(self.mod, "check_update_notice", side_effect=AssertionError("update check")):
            self.assertEqual(self.mod.ensure_binary(), os.path.abspath(stub))
        net.assert_not_called()

    def test_explicit_override_that_is_missing_fails_closed(self):
        missing = os.path.join(self.tmp.name, "nope", "agentsecrets")
        os.environ["AGENTSECRETS_BINARY"] = missing
        with mock.patch.object(self.mod.urllib.request, "urlopen", side_effect=AssertionError("must not download")):
            with self.assertRaisesRegex(Exception, "not an executable file"):
                self.mod.ensure_binary()

    def test_bundled_platform_wheel_binary_wins_without_network(self):
        pkg = os.path.join(self.tmp.name, "site-packages", "agentsecrets")
        bundled = make_executable(os.path.join(pkg, "bin", "agentsecrets"))
        self.mod.__file__ = os.path.join(pkg, "binary.py")
        with mock.patch.object(self.mod.urllib.request, "urlopen", side_effect=AssertionError("network call")) as net, \
             mock.patch.object(self.mod, "check_update_notice", side_effect=AssertionError("update check")):
            self.assertEqual(self.mod.ensure_binary(), bundled)
        net.assert_not_called()

    def test_bundled_beats_a_cached_binary(self):
        pkg = os.path.join(self.tmp.name, "site-packages", "agentsecrets")
        bundled = make_executable(os.path.join(pkg, "bin", "agentsecrets"))
        self.mod.__file__ = os.path.join(pkg, "binary.py")
        home = os.path.join(self.tmp.name, "cache-home")
        os.environ["AGENTSECRETS_HOME"] = home
        make_executable(os.path.join(home, "bin", f"agentsecrets_{self.mod.VERSION}"))
        self.assertEqual(self.mod.ensure_binary(), bundled)

    def test_cached_binary_in_explicit_home_avoids_download(self):
        self.mod.__file__ = os.path.join(self.tmp.name, "site-packages", "agentsecrets", "binary.py")
        home = os.path.join(self.tmp.name, "cache-home")
        os.environ["AGENTSECRETS_HOME"] = home
        cached = make_executable(os.path.join(home, "bin", f"agentsecrets_{self.mod.VERSION}"))
        with mock.patch.object(self.mod.urllib.request, "urlopen", side_effect=AssertionError("network call")) as net, \
             mock.patch.object(self.mod, "check_update_notice", side_effect=AssertionError("update check")):
            self.assertEqual(self.mod.ensure_binary(), cached)
        net.assert_not_called()

    def test_explicit_home_is_used_even_when_default_is_writable(self):
        home = os.path.join(self.tmp.name, "explicit-home")
        os.environ["AGENTSECRETS_HOME"] = home
        self.assertEqual(self.mod.writable_home(), os.path.abspath(home))
        self.assertTrue(os.path.isdir(home))

    def test_home_falls_back_to_tmp_when_default_is_unwritable(self):
        tmp_home = os.path.join(self.tmp.name, "tmp")
        os.makedirs(tmp_home, exist_ok=True)
        with mock.patch.object(self.mod, "_ensure_writable_dir", return_value=False), \
             mock.patch.object(self.mod.tempfile, "gettempdir", return_value=tmp_home):
            got = self.mod.writable_home()
        self.assertEqual(got, os.path.join(tmp_home, "agentsecrets-home"))
        self.assertTrue(os.path.isdir(got))

    def test_download_fallback_is_the_only_path_that_checks_for_updates(self):
        self.mod.__file__ = os.path.join(self.tmp.name, "site-packages", "agentsecrets", "binary.py")
        home = os.path.join(self.tmp.name, "empty-home")
        os.environ["AGENTSECRETS_HOME"] = home
        with mock.patch.object(self.mod, "check_update_notice") as notice, \
             mock.patch.object(self.mod.urllib.request, "urlopen", side_effect=OSError("offline")), \
             mock.patch.object(self.mod.shutil, "which", return_value=None):
            with self.assertRaisesRegex(Exception, "Failed to download AgentSecrets binary"):
                self.mod.ensure_binary()
        notice.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
