import os
import stat
import subprocess
import sys
import tempfile
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "src")


def _make_executable(path, body="#!/bin/sh\necho STUB\n"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


class ModuleEntrypointTests(unittest.TestCase):
    def test_python_m_agentsecrets_invokes_binary_via_main(self):
        # A stub stands in for the bundled Go binary so the test needs no
        # network and no real binary. The point is that `python -m agentsecrets`
        # reaches main() -> ensure_binary() -> the resolved binary.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        stub = _make_executable(
            os.path.join(tmp.name, "agentsecrets"),
            "#!/bin/sh\necho STUB_VERSION_4_0_0\n",
        )
        env = dict(os.environ, AGENTSECRETS_BINARY=stub)
        proc = subprocess.run(
            [sys.executable, "-m", "agentsecrets", "--version"],
            cwd=SRC,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("STUB_VERSION_4_0_0", proc.stdout)

    def test_python_m_agentsecrets_fails_closed_without_binary(self):
        # A dangling AGENTSECRETS_BINARY is refused immediately, so the
        # entrypoint must exit non-zero rather than hang or silently succeed.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = dict(os.environ, AGENTSECRETS_BINARY=os.path.join(tmp.name, "does-not-exist"))
        proc = subprocess.run(
            [sys.executable, "-m", "agentsecrets", "--version"],
            cwd=SRC,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
