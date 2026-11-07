"""Hatchling build hook for the AgentSecrets PyPI launcher.

When ``AGENTSECRETS_WHEEL_BINARY`` and ``AGENTSECRETS_WHEEL_TAG`` are both set,
this hook bundles the prebuilt Go binary into the wheel and pins the wheel's
platform tag. This is what turns the pure launcher into a platform wheel that
ships the binary on disk at install time (no GitHub fetch at boot).

With neither env var set, the hook is a no-op and a pure ``py3-none-any``
launcher wheel is produced, used as the musl/unsupported-platform fallback.
"""

import os

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomPlatformHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version, build_data):
        binary = os.environ.get("AGENTSECRETS_WHEEL_BINARY")
        tag = os.environ.get("AGENTSECRETS_WHEEL_TAG")

        if not binary or not tag:
            # Pure launcher build: nothing to bundle.
            return

        if not os.path.isfile(binary):
            raise RuntimeError(
                f"AGENTSECRETS_WHEEL_BINARY points at {binary!r}, which is not a file"
            )

        build_data["force_include"][os.path.abspath(binary)] = "agentsecrets/bin/agentsecrets"
        build_data["pure_python"] = False
        build_data["infer_tag"] = False
        build_data["tag"] = tag
