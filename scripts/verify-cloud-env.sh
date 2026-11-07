#!/usr/bin/env bash
# Verify cloud mode in production, zero config (v4 Phase 2).
#
# Builds the linux/amd64 Go binary and the two platform artifacts (PyPI wheel +
# npm platform package), installs them on the host, then runs `agentsecrets
# mode` and `agentsecrets env --` inside a rootless user+mount+network namespace
# (unshare -Urmn) with a read-only HOME:
#
#   1. Cloud is selected from AGENTSECRETS_MODE=cloud ALONE — no `agentsecrets
#      mode cloud` command and no writable ~/.agentsecrets config file in the
#      image. A fresh, empty, read-only HOME proves the selection needs nothing.
#   2. `agentsecrets env -- <cmd>` resolves through the cloud resolver. Offline
#      (no network egress in the namespace) the resolver is unreachable, so the
#      command MUST fail closed: the child is never exec'd, there is no silent
#      local keychain fallback, and the injected-secret count stays 0.
#
# The positive injected-env count is proven by the in-process Go tests
# (TestPhase2CloudZeroConfig / TestSecretsForEnvCloudFetchesWorkloadEnv), which
# mock the resolver. This script proves the container-surface contract: the
# bundled binary reaches cloud mode from two platform env vars and fails closed
# when the resolver is down.
#
# Optional live success run: set LIVE=1 and a real AGENTSECRETS_TOKEN in the
# environment. The script then uses unshare -Urm (network shared) so the bundled
# binary can reach the real resolver, and captures the injected-secret count and
# exit code from `agentsecrets env --` directly.
#
# This is a genuine read-only-FS / no-network container surface: Docker is not
# required locally. It reproduces what a read-only Docker/Vercel/Lambda layer
# does at runtime.

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
echo "[verify] binary: $("$BIN_DIR/agentsecrets" --version 2>&1 | head -1 || true)"

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
NPM_BIN="$NPM_PROJECT/node_modules/.bin/agentsecrets"

# The marker the child would create if `env --` ever exec'd it. Its absence is
# the proof of fail-closed: the child must never run when resolution fails.
MARKER="/tmp/agentsecrets_phase2_child_ran"
rm -f "$MARKER"

run_surface() {
  local label="$1" bin="$2"
  echo "=== $label ==="

  local out rc injected
  out="$(unshare -Urmn -- bash -c '
    set -uo pipefail
    WORK="'"$WORK"'"
    BIN="'"$bin"'"
    LABEL="'"$label"'"
    MARKER="'"$MARKER"'"
    rm -f "$MARKER"

    # Fresh, empty, read-only HOME: cloud selection must not need any config.
    RO_HOME="$(mktemp -d)"
    mount --bind "$RO_HOME" "$RO_HOME"
    mount -o remount,ro,bind "$RO_HOME" "$RO_HOME"
    export HOME="$RO_HOME"

    export AGENTSECRETS_MODE=cloud
    export AGENTSECRETS_TOKEN="fake-workload-token"

    echo "--- mode ---"
    MODE_OUT="$($BIN mode 2>&1)"
    echo "$MODE_OUT"

    if ! echo "$MODE_OUT" | grep -qE "Mode:[[:space:]]+cloud"; then
      echo "[FAIL] $LABEL: mode is not cloud"; exit 1
    fi
    if ! echo "$MODE_OUT" | grep -qE "Selected by:[[:space:]]+AGENTSECRETS_MODE"; then
      echo "[FAIL] $LABEL: cloud not selected by AGENTSECRETS_MODE"; exit 1
    fi

    echo "--- env -- (offline, resolver unreachable) ---"
    # Child touches MARKER; under fail-closed it must never run.
    set +e
    ENV_OUT="$($BIN env -- /bin/sh -c "touch $MARKER" 2>&1)"
    rc=$?
    set -e
    echo "$ENV_OUT"
    echo "exit=$rc"

    # Injected count is read from the success line; offline it is never printed.
    injected=$(echo "$ENV_OUT" | grep -oE "Injected [0-9]+ secrets" | grep -oE "[0-9]+" || true)
    [ -z "$injected" ] && injected=0

    if [ "$rc" -eq 0 ]; then
      echo "[FAIL] $LABEL: env -- exited 0 with an unreachable resolver (not fail-closed)"; exit 1
    fi
    if [ -e "$MARKER" ]; then
      echo "[FAIL] $LABEL: child was exec'"'"'d despite resolution failure (local fallback?)"; exit 1
    fi
    if [ "$injected" != "0" ]; then
      echo "[FAIL] $LABEL: $injected secrets injected on failure (expected 0)"; exit 1
    fi
    echo "[OK] $LABEL: cloud via AGENTSECRETS_MODE, fail-closed, 0 injected, exit=$rc"
  ')"
  rc=$?
  echo "$out"
  if [ "$rc" -ne 0 ]; then
    echo "[verify] FAILED on $label (rc=$rc)"
    return 1
  fi
  return 0
}

if ! run_surface "python wrapper" "$VENV/bin/agentsecrets"; then
  echo "[verify] FAILED"
  exit 1
fi
if ! run_surface "npm wrapper" "$NPM_BIN"; then
  echo "[verify] FAILED"
  exit 1
fi

# Optional live success run against the real resolver.
if [ "${LIVE:-0}" = "1" ] && [ -n "${AGENTSECRETS_TOKEN:-}" ]; then
  echo "=== live run (real resolver) ==="
  LIVE_OUT="$(unshare -Urm -- bash -c '
    set -uo pipefail
    WORK="'"$WORK"'"
    BIN="'"$VENV/bin/agentsecrets"'"
    RO_HOME="$(mktemp -d)"
    export HOME="$RO_HOME"
    export AGENTSECRETS_MODE=cloud
    export AGENTSECRETS_TOKEN="'"$AGENTSECRETS_TOKEN"'"
    set +e
    OUT="$("$BIN" env -- /bin/sh -c "echo LIVE_OK; env | grep -cE \"^[A-Z_]+=\" " 2>&1)"
    rc=$?
    set -e
    echo "$OUT"
    echo "exit=$rc"
  ')"
  echo "$LIVE_OUT"
else
  echo "[verify] skipping live run (set LIVE=1 and AGENTSECRETS_TOKEN for a real success capture)"
fi

echo "[verify] PASSED: cloud mode in production, zero config — selection + fail-closed verified"
