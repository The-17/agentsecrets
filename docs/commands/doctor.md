# agentsecrets doctor

> Diagnose and self-heal your AgentSecrets installation and local security trust chain.

## Usage

```bash
agentsecrets doctor [--check-only] [--json]
```

## Description

`agentsecrets doctor` performs a comprehensive, deterministic health audit of your local AgentSecrets installation, the underlying `keychain-auth` capability-bounding daemon, and OS credential storage.

Whenever a broken state or policy denial is detected, the doctor automatically executes safe self-healing repairs and re-verifies your installation before exiting.

### The 8 Local Trust Chain Checks

The doctor verifies every link in the local trust chain:

1. **Daemon Installed & Versioned**: Verifies `keychain-auth` is installed and meets the required minimum version (`>= v3.3.0`).
2. **Daemon Running & Socket Dialable**: Checks that the daemon background service is active and its IPC socket (`/run/keychain-auth/agent.sock` on Linux, `~/Library/Application Support/keychain-auth/agent.sock` on macOS, or Named Pipe `\\.\pipe\keychain-auth` on Windows) is dialable.
3. **Daemon Up-to-Date**: Ensures the running daemon process is not serving outdated or orphaned code from a previous version.
4. **Binary Registered**: Confirms that this specific `agentsecrets` binary path and its SHA-256 hash are registered in the daemon's trust store.
5. **Live Policy Authorization**: Probes the daemon's in-memory policy to verify that the active session is genuinely granted access.
6. **Socket Integrity**: Detects and cleans up orphaned or stale socket files.
7. **Trust Store Permissions**: Audits `/etc/keychain-auth/config.json` to guarantee it is not world-writable (hardened to `0640 root:keychain-auth`).
8. **Credential Decryption**: Verifies that stored credentials and workspace keys can be decrypted and read by the authorized binary.

---

## Automatic Self-Healing (`RegisterAndActivate`)

When run without flags, `agentsecrets doctor` repairs fixable issues automatically using the `RegisterAndActivate` sequence:
1. **Interactive Elevation Caching**: Prompts for your password up-front (if system elevation is required) so password prompts are never hidden behind terminal spinners.
2. **Atomic Authorization**: Invokes `keychain-auth authorize <path> <service>` to write the binary hash and path into the trust store.
3. **Daemon Restart**: Automatically restarts the daemon process so in-memory policy immediately updates.
4. **Live Verification**: Reconnects and probes live policy to prove the fix succeeded before returning.

> **Security Guarantee**: The doctor cannot bypass security policies. Authorization still routes through `keychain-auth`'s strict privilege boundary and requires administrator confirmation when modifying system-wide trust stores.

---

## Flags

### `--check-only`
Perform a strictly read-only inspection. Reports all passing, warning, and broken findings without attempting repairs or prompting for elevation.

```bash
agentsecrets doctor --check-only
```

### `--json`
Emit the full diagnostic report as structured JSON. Exits with status code `0` if healthy, or code `1` if any check fails or is broken. Perfect for CI/CD pipelines, container startup gates, and monitoring scripts.

```bash
agentsecrets doctor --json
```

```json
{
  "healthy": true,
  "os": "linux",
  "is_wsl": true,
  "has_systemd": false,
  "keychain_auth_path": "/home/user/.agentsecrets/bin/keychain-auth",
  "daemon_version": "3.3.0",
  "daemon_mode": "user",
  "socket_path": "/home/user/.config/keychain-auth/agent.sock",
  "self_path": "/home/user/.agentsecrets/bin/agentsecrets",
  "findings": [
    {
      "id": "daemon_installed",
      "title": "keychain-auth installed",
      "status": "ok",
      "fixable": false
    },
    {
      "id": "daemon_running",
      "title": "keychain-auth daemon running",
      "status": "ok",
      "fixable": false
    },
    {
      "id": "binary_authorized",
      "title": "this binary authorized",
      "status": "ok",
      "fixable": false
    }
  ]
}
```

---

## When to Run `agentsecrets doctor`

Run the doctor whenever:
- You upgraded `agentsecrets` or `keychain-auth` via Homebrew, npm, or pip.
- A command fails with `[SEC-403]` (Binary Authorization Denied).
- You moved, copied, or recompiled the `agentsecrets` binary to a new location.
- Your terminal reports socket connection errors or stale daemon states.
- Setting up a fresh development machine or CI/CD runner.
