#!/usr/bin/env bash
# Verify boot-path availability (v4 Phase 3).
#
# Builds the linux/amd64 Go binary and the two platform artifacts (PyPI wheel +
# npm platform package), installs them on the host, then proves the
# `agentsecrets` command is reachable at boot across every surface WITHOUT the
# operator hand-editing PATH:
#
#   * PyPI console script `agentsecrets` (on PATH when venv/bin is on PATH)
#   * PyPI module form `python -m agentsecrets` (PATH-independent)
#   * npm bin link `node_modules/.bin/agentsecrets`
#   * npm `npx agentsecrets`
#
# and that, with a MINIMAL PATH that hides both console-script bin dirs, the
# bare `agentsecrets` command is NOT found while the module form, the explicit
# npm bin path, and `npx` all still resolve. That is the gap the -m / npx forms
# close in Docker, docker-compose, Vercel, and GitHub Actions.
#
# The checks run inside an unshare -Urmn namespace with a read-only HOME and no
# network, the same container surface as Phases 1/2. No GitHub fetch and no
# writable ~/.agentsecrets are needed because Phase 1 bundles the binary.
# Docker is not required locally.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

export PATH="$HOME/tools/node/bin:$PATH"

GO="${GO_BIN:-/usr/lib/go/bin/go}"
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

# 2. Build the linux platform wheel.
echo "[verify] building platform wheel"
AGENTSECRETS_WHEEL_BINARY="$BIN_DIR/agentsecrets" \
AGENTSECRETS_WHEEL_TAG="py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64" \
  "$PYTHON" -m build --wheel --no-isolation --outdir "$WORK/dist" pypi/
WHEEL="$(ls "$WORK/dist"/agentsecrets_cli-*manylinux_2_17_x86_64*.whl | head -1)"

# 3. Build the npm launcher + linux-x64 platform package tarballs.
echo "[verify] packing npm launcher + platform package"
"$NPM" pack --pack-destination "$WORK/dist" npm/ >/dev/null
LAUNCHER_TGZ="$(ls "$WORK/dist"/the-17-agentsecrets-*.tgz | head -1)"
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

# Export the paths so the namespace child inherits them (no nested quoting).
export WORK VENV NPM_PROJECT
export NODE_BIN_DIR="$HOME/tools/node/bin"

echo "[verify] running boot-path checks inside read-only / no-network namespace"
RC=0
unshare -Urmn -- bash -c '
  set -uo pipefail
  RC=0
  ok()   { echo "[OK]   $1"; }
  fail() { echo "[FAIL] $1"; RC=1; }
  check_version() {
    local label="$1"; shift
    local out rc
    set +e
    out="$("$@" 2>&1)"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ] && echo "$out" | grep -qi "agentsecrets version"; then
      ok "$label  ->  $(echo "$out" | head -1)"
    else
      fail "$label (rc=$rc): $(echo "$out" | head -1)"
    fi
  }

  # Fresh, empty, read-only HOME: boot-path resolution must not need any config.
  RO_HOME="$(mktemp -d)"
  mount --bind "$RO_HOME" "$RO_HOME" || { fail "bind mount"; exit 1; }
  mount -o remount,ro,bind "$RO_HOME" "$RO_HOME" || { fail "ro remount"; exit 1; }
  export HOME="$RO_HOME"

  # npm must not try to write logs into the read-only HOME or hit the network.
  export npm_config_cache="$WORK/npmcache"
  export npm_config_offline=true
  export npm_config_audit=false
  export npm_config_fund=false
  mkdir -p "$npm_config_cache"

  SYS_PATH="$NODE_BIN_DIR:/usr/bin:/bin"

  echo "--- full PATH: console script + module + npm bin + npx ---"
  export PATH="$VENV/bin:$NPM_PROJECT/node_modules/.bin:$SYS_PATH"
  check_version "PyPI console script (agentsecrets)"            "$VENV/bin/agentsecrets" --version
  check_version "PyPI module form (python -m agentsecrets)"      "$VENV/bin/python" -m agentsecrets --version
  check_version "npm bin link (node_modules/.bin/agentsecrets)" "$NPM_PROJECT/node_modules/.bin/agentsecrets" --version
  check_version "npm npx (npx agentsecrets)"                     bash -c "cd \"$NPM_PROJECT\" && npx agentsecrets --version"

  echo "--- minimal PATH: bare command hidden, -m / explicit bin / npx still resolve ---"
  export PATH="$SYS_PATH"
  if command -v agentsecrets >/dev/null 2>&1; then
    fail "bare agentsecrets unexpectedly found on minimal PATH"
  else
    ok "bare agentsecrets is NOT on minimal PATH (the gap the deploy examples close)"
  fi
  check_version "PyPI module form with minimal PATH"            "$VENV/bin/python" -m agentsecrets --version
  check_version "npm explicit bin path with minimal PATH"       "$NPM_PROJECT/node_modules/.bin/agentsecrets" --version
  check_version "npm npx with minimal PATH"                     bash -c "cd \"$NPM_PROJECT\" && npx agentsecrets --version"

  exit $RC
' || RC=$?

if [ "$RC" -ne 0 ]; then
  echo "[verify] FAILED (rc=$RC)"
  exit 1
fi

echo "[verify] PASSED: boot-path availability verified across PyPI + npm surfaces"
