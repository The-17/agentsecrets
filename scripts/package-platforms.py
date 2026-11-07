#!/usr/bin/env python3
"""Package AgentSecrets for container-safe install (v4 Phase 1).

Builds, for every supported (os, arch) pair:
  * a PyPI **platform wheel** that bundles the Go binary on disk, plus the pure
    ``py3-none-any`` launcher wheel (musl / unsupported-platform fallback);
  * an npm **platform package** (``@the-17/agentsecrets-<platform>-<arch>``)
    that bundles the Go binary, plus the npm launcher tarball.

The wrappers resolve the bundled binary first, so an install in a read-only,
no-network container works with zero GitHub calls.

Usage:
    scripts/package-platforms.py --version 4.0.0
    scripts/package-platforms.py --version 4.0.0 --bin-dir ./prebuilt
    scripts/package-platforms.py --version 4.0.0 --go-build   # cross-compile

Outputs everything to ./dist (override with --outdir).
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (goos, goarch, npm_os, npm_cpu, wheel_tag)
PLATFORMS = [
    ("linux", "amd64", "linux", "x64",
     "py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64"),
    ("linux", "arm64", "linux", "arm64",
     "py3-none-manylinux_2_17_aarch64"),
    ("darwin", "amd64", "darwin", "x64",
     "py3-none-macosx_10_9_x86_64"),
    ("darwin", "arm64", "darwin", "arm64",
     "py3-none-macosx_11_0_arm64"),
    ("windows", "amd64", "win32", "x64",
     "py3-none-win_amd64"),
    ("windows", "arm64", "win32", "arm64",
     "py3-none-win_arm64"),
]


def log(msg):
    print(f"[package-platforms] {msg}", flush=True)


def run(cmd, **kw):
    log("+ " + " ".join(cmd))
    subprocess.run(cmd, check=True, **kw)


def which(tool, env_name):
    found = os.environ.get(env_name)
    if found and shutil.which(found):
        return found
    found = shutil.which(tool)
    if not found:
        sys.exit(f"ERROR: {tool!r} not found on PATH (set {env_name})")
    return found


def read_version():
    pyproject = os.path.join(REPO_ROOT, "pypi", "pyproject.toml")
    with open(pyproject) as f:
        for line in f:
            if line.startswith("version = "):
                return line.split("=", 1)[1].strip().strip('"')
    sys.exit("ERROR: could not read version from pypi/pyproject.toml")


def cross_compile(go, goos, goarch, version, out_dir):
    binary_name = "agentsecrets.exe" if goos == "windows" else "agentsecrets"
    out_path = os.path.join(out_dir, f"{goos}_{goarch}", binary_name)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    env = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="0")
    run([
        go, "build", "-trimpath",
        f"-ldflags=-s -w -X github.com/The-17/agentsecrets/cmd/agentsecrets/commands.Version={version}",
        "-o", out_path, "./cmd/agentsecrets/",
    ], env=env, cwd=REPO_ROOT)
    return out_path


def build_python_wheels(python, version, binaries_by_tag, out_dir):
    pypi_dir = os.path.join(REPO_ROOT, "pypi")
    # Pure launcher wheel (no binary) - musl / unsupported fallback.
    log("building pure launcher wheel (py3-none-any)")
    run([python, "-m", "build", "--wheel", "--no-isolation",
         "--outdir", out_dir], cwd=pypi_dir)

    # Platform wheels - each bundles one binary.
    for tag, binary in binaries_by_tag.items():
        log(f"building platform wheel {tag} <- {os.path.basename(binary)}")
        env = dict(os.environ,
                   AGENTSECRETS_WHEEL_BINARY=os.path.abspath(binary),
                   AGENTSECRETS_WHEEL_TAG=tag)
        run([python, "-m", "build", "--wheel", "--no-isolation",
             "--outdir", out_dir], cwd=pypi_dir, env=env)


def build_npm_packages(npm, version, binaries_by_platform, out_dir):
    npm_dir = os.path.join(REPO_ROOT, "npm")

    # Launcher tarball.
    log("packing npm launcher")
    run([npm, "pack", "--pack-destination", out_dir], cwd=npm_dir)

    # Platform packages.
    for (goos, goarch, npm_os, npm_cpu, _tag), binary in binaries_by_platform.items():
        pkg_name = f"@the-17/agentsecrets-{npm_os}-{npm_cpu}"
        with tempfile.TemporaryDirectory() as tmp:
            pkg_dir = os.path.join(tmp, pkg_name)
            bin_dir = os.path.join(pkg_dir, "bin")
            os.makedirs(bin_dir, exist_ok=True)
            dest_bin = os.path.join(bin_dir, os.path.basename(binary))
            shutil.copy(binary, dest_bin)
            os.chmod(dest_bin, 0o755)
            pkg_json = {
                "name": pkg_name,
                "version": version,
                "os": [npm_os],
                "cpu": [npm_cpu],
                "license": "MIT",
                "files": [f"bin/{os.path.basename(binary)}"],
                "repository": {
                    "type": "git",
                    "url": "git+https://github.com/The-17/agentsecrets.git",
                },
            }
            with open(os.path.join(pkg_dir, "package.json"), "w") as f:
                json.dump(pkg_json, f, indent=2)
            log(f"packing {pkg_name}")
            run([npm, "pack", "--pack-destination", out_dir], cwd=pkg_dir)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default=None, help="package version (default: from pyproject.toml)")
    ap.add_argument("--outdir", default=os.path.join(REPO_ROOT, "dist"))
    ap.add_argument("--go-build", action="store_true",
                    help="cross-compile the Go binary for every platform (default)")
    ap.add_argument("--bin-dir", default=None,
                    help="directory of prebuilt binaries named <goos>_<goarch>/agentsecrets[.exe]")
    ap.add_argument("--skip-go", action="store_true",
                    help="use --bin-dir semantics even if go-build implied")
    args = ap.parse_args()

    version = args.version or read_version()
    os.makedirs(args.outdir, exist_ok=True)

    go = which("go", "GO_BIN")
    python = which("python3", "PYTHON_BIN")
    npm = which("npm", "NPM_BIN")

    binaries_by_tag = {}
    binaries_by_platform = {}

    if args.bin_dir:
        for (goos, goarch, npm_os, npm_cpu, tag) in PLATFORMS:
            name = "agentsecrets.exe" if goos == "windows" else "agentsecrets"
            p = os.path.join(args.bin_dir, f"{goos}_{goarch}", name)
            if not os.path.isfile(p):
                sys.exit(f"ERROR: missing prebuilt binary {p}")
            binaries_by_tag[tag] = p
            binaries_by_platform[(goos, goarch, npm_os, npm_cpu, tag)] = p
    else:
        # Cross-compile into a temp tree, then map to tags.
        with tempfile.TemporaryDirectory() as build_dir:
            built = {}
            for (goos, goarch, npm_os, npm_cpu, tag) in PLATFORMS:
                if args.skip_go:
                    sys.exit("--skip-go requires --bin-dir")
                out = cross_compile(go, goos, goarch, version, build_dir)
                built[(goos, goarch, npm_os, npm_cpu, tag)] = out
            for key, p in built.items():
                binaries_by_tag[key[4]] = p
                binaries_by_platform[key] = p

    build_python_wheels(python, version, binaries_by_tag, args.outdir)
    build_npm_packages(npm, version, binaries_by_platform, args.outdir)

    log("done. artifacts in " + args.outdir)
    for f in sorted(os.listdir(args.outdir)):
        log("  " + f)


if __name__ == "__main__":
    main()
