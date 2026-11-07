#!/usr/bin/env bash
# Verify container-safe install (v4 Phase 1).
#
# Builds the linux/amd64 Go binary and the two platform artifacts (PyPI wheel +
# npm platform package), installs them on the host, then runs `agentsecrets
# version` and `agentsecrets mode` inside a rootless user+mount+network
# namespace (unshare -Urmn) with a read-only HOME. The network namespace has no
# routes, so any GitHub download attempt fails immediately. If the binary is
# truly bundled, both commands exit 0 with no cache file written and no network
# call.
#
# This is a genuine read-only-FS / no-network container surface: Docker is not
# required locally. It reproduces what a read-only Docker/Vercel/Lambda layer
# does at runtime.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

export PATH="$HOME/tools/node/bin:$PATH"

GO="${GO_BIN:-/usr/lib/go/bin/go}"
# Prefer a repo venv that already has hatchling (used for --no-isolation builds).
if [ -x "$REPO_ROOT/env/bin/python" ]; then
  PYTHON="${PYTHON_BIN:-$REPO_ROOT/env/bin/python}"
else
  PYTHON="${PYTHON_BIN:-python3}"
fi
NPM="${NPM_BIN:-$(command -v npm)}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

VERSION="$(grep -m1 '^version = ' pypi/pyproject.toml | sed 's/.*"\(.*\)"/\1/')"
echo "[verify] version=$VERSION work=$WORK"

# 1. Cross-compile the linux/amd64 binary.
BIN_DIR="$WORK/bin"
mkdir -p "$BIN_DIR"
echo "[verify] building linux/amd64 binary"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 "$GO" build -trimpath \
  -ldflags="-s -w -X github.com/The-17/agentsecrets/cmd/agentsecrets/commands.Version=$VERSION" \
  -o "$BIN_DIR/agentsecrets" ./cmd/agentsecrets/
chmod 0755 "$BIN_DIR/agentsecrets"
echo "[verify] binary: $("$BIN_DIR/agentsecrets" --version 2>&1 | head -1 || true)"

# 2. Build the linux platform wheel.
echo "[verify] building platform wheel"
AGENTSECRETS_WHEEL_BINARY="$BIN_DIR/agentsecrets" \
AGENTSECRETS_WHEEL_TAG="py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64" \
  "$PYTHON" -m build --wheel --no-isolation --outdir "$WORK/dist" pypi/
WHEEL="$(ls "$WORK/dist"/agentsecrets_cli-*manylinux_2_17_x86_64*.whl | head -1)"
echo "[verify] wheel: $WHEEL"

# 3. Build the npm launcher + linux-x64 platform package tarballs.
echo "[verify] packing npm launcher"
"$NPM" pack --pack-destination "$WORK/dist" npm/ >/dev/null
LAUNCHER_TGZ="$(ls "$WORK/dist"/the-17-agentsecrets-*.tgz | head -1)"

echo "[verify] packing npm platform package (linux-x64)"
PLAT_DIR="$WORK/npmplat"
PLAT_NAME="@the-17/agentsecrets-linux-x64"
mkdir -p "$PLAT_DIR/$PLAT_NAME/bin"
cp "$BIN_DIR/agentsecrets" "$PLAT_DIR/$PLAT_NAME/bin/agentsecrets"
chmod 0755 "$PLAT_DIR/$PLAT_NAME/bin/agentsecrets"
cat > "$PLAT_DIR/$PLAT_NAME/package.json" <<JSON
{
  "name": "$PLAT_NAME",
  "version": "$VERSION",
  "os": ["linux"],
  "cpu": ["x64"],
  "license": "MIT",
  "files": ["bin/agentsecrets"]
}
JSON
"$NPM" pack --pack-destination "$WORK/dist" "$PLAT_DIR/$PLAT_NAME" >/dev/null
PLAT_TGZ="$(ls "$WORK/dist"/the-17-agentsecrets-linux-x64-*.tgz | head -1)"
echo "[verify] launcher: $LAUNCHER_TGZ"
echo "[verify] platform: $PLAT_TGZ"

# 4. Install on the host (writable) into scratch trees.
echo "[verify] installing wheel into venv"
VENV="$WORK/venv"
"$PYTHON" -m venv "$VENV"
"$VENV/bin/pip" install --quiet "$WHEEL"

echo "[verify] installing npm packages (offline)"
NPM_PROJECT="$WORK/npmproj"
mkdir -p "$NPM_PROJECT"
( cd "$NPM_PROJECT"
  "$NPM" init -y >/dev/null 2>&1
  "$NPM" install --no-optional --offline --no-audit --no-fund "$LAUNCHER_TGZ" >/dev/null
  "$NPM" install --offline --no-audit --no-fund "$PLAT_TGZ" >/dev/null
)

# 5. Run inside the container namespace.
echo "[verify] running inside read-only / no-network namespace"
RC=0
unshare -Urmn -- bash -c '
  set -euo pipefail
  WORK="'"$WORK"'"
  VENV="$WORK/venv"
  NPM_BIN="$WORK/npmproj/node_modules/.bin/agentsecrets"

  # Read-only HOME: bind-mount an empty dir over a scratch HOME, remounted ro.
  RO_HOME="$(mktemp -d)"
  mount --bind "$RO_HOME" "$RO_HOME"
  mount -o remount,ro,bind "$RO_HOME" "$RO_HOME"
  export HOME="$RO_HOME"

  # Prove no network egress exists.
  if ip route show >/dev/null 2>&1 && [ -n "$(ip route show 2>/dev/null)" ]; then
    echo "[verify:container] WARNING: routes present"
  fi

  echo "--- python wrapper: --version ---"
  "$VENV/bin/agentsecrets" --version
  echo "--- python wrapper: mode ---"
  "$VENV/bin/agentsecrets" mode
  echo "--- npm wrapper: --version ---"
  "$NPM_BIN" --version
  echo "--- npm wrapper: mode ---"
  "$NPM_BIN" mode

  # Assert no cached binary was written (proves no download path taken).
  CACHE="$RO_HOME/.agentsecrets/bin"
  if [ -d "$CACHE" ] && ls "$CACHE"/agentsecrets_* >/dev/null 2>&1; then
    echo "[verify:container] FAIL: cache binary appeared (download path taken)"
    ls -la "$CACHE"
    exit 1
  fi
  echo "[verify:container] OK: no cache binary, commands succeeded with no network"
' || RC=$?

if [ "$RC" -ne 0 ]; then
  echo "[verify] FAILED (rc=$RC)"
  exit 1
fi

echo "[verify] PASSED: container-safe install verified"
