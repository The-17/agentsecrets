# Changelog

## 1.2.0

### Added

- **Permission tiers, enforced at registration.** Every tool carries a tier
  (`read`, `write`, `destructive`). Write and destructive tools are refused
  unless a human set `AGENTSECRETS_MCP_ALLOW_WRITES=true` in the MCP client
  configuration. Anything other than the exact string `true` fails closed. A
  model cannot set its own process environment, so it cannot open the gate.
  `auth_status` reports the current state under `permissions`.
- **`secrets_rotation_status`** — read a secret's rotation cadence and version
  history. Metadata only, never a value. Read tier, always available.
- **`secrets_rotate`** — stage a new pending version of a secret, value-blind:
  `generate` mints a random value, `command` captures a provider CLI's stdout,
  or `value` travels inside the single call. The new value is encrypted before
  transit and never returned or logged. Destructive tier. Promotion, rollback,
  and abort stay human-only: they need the password and belong in the terminal.
- **`agent_token_rotate`** — rotate a workload token with overlap (routine) or
  immediate revoke (compromise). Destructive tier; requires `confirm: true`.
  The new token value is never returned.

### Changed

- **Tool surface is 30** (was 27).
- **Cloud mode is now gated too.** Previously only the CLI bridge enforced
  tiers; cloud mode talks to the control plane and resolver directly and never
  passes through the CLI. The gate now lives at tool registration, so it covers
  both transports.
- Local mode spawns `agentsecrets mcp <verb>`. The older `mcp bridge <verb>`
  spelling is still accepted by the CLI, so either pairing works.

### Security

- Tier classification is checked at startup: registering a tool with no tier is
  a crash on boot, not a silent bypass.
- No tool edits the allowlist, and no tool promotes, rolls back, or aborts a
  rotation.
