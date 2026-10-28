# agentsecrets mcp

> Model Context Protocol server and the machine-readable bridge for Claude Desktop, Cursor, Claude Code, Codex, and OpenClaw.

## Usage

```bash
# Start the MCP server over stdio (launched by an AI client)
agentsecrets mcp serve

# Configure every detected AI client and install the agent skill
agentsecrets mcp install

# Run one privileged operation and print a JSON envelope (called by the bridge)
agentsecrets mcp <verb> [json-args]
```

`agentsecrets mcp <verb>` is the interface the published bridge
(`@the-17/agentsecrets-mcp`) calls. The older spelling
`agentsecrets mcp bridge <verb>` still works: the word `bridge` is accepted and
ignored, so existing client configurations keep running.

## Permission model

Mutating verbs are refused unless a human set `AGENTSECRETS_MCP_ALLOW_WRITES=true`
in the MCP client configuration. A model cannot set its own process environment,
so it cannot enable writes. Anything other than the exact value `true` fails
closed.

Read verbs stay available with writes off: `ping`, `status`, `auth.export`,
`secrets.list`, `secrets.diff`, `secrets.rotation_status`, `proxy.call`,
`proxy.status`, `project.list`, `workspace.list`, `workspace.members`,
`agent.list`, `logs.list`, `logs.summary`, `logs.detail`.

Gated verbs: `secrets.set`, `secrets.delete`, `secrets.pull`, `secrets.push`,
`secrets.rotate`, `project.create`, `project.use`, `project.update`,
`project.delete`, `workspace.create`, `workspace.switch`, `agent.delete`,
`agent.token_issue`, `agent.token_rotate`.

There is no bridge verb that edits the allowlist. Widening egress stays
human-only.

## Rotation

Staging is available to an agent; promotion is not.

```bash
# Stage a new pending version, value-blind (generate, capture, or inline)
agentsecrets mcp secrets.rotate '{"key":"STRIPE_KEY","generate":true,"confirm":true}'
agentsecrets mcp secrets.rotate '{"key":"STRIPE_KEY","command":"vault kv get -field=key secret/x","confirm":true}'

# Read cadence and version history (metadata only)
agentsecrets mcp secrets.rotation_status '{"key":"STRIPE_KEY"}'

# Promotion, rollback, and abort are human-only: they need the password
agentsecrets secrets rotate STRIPE_KEY --promote
```

## Protocol

Arguments are a single JSON object, on argv or stdin. Stdout is always exactly
one envelope, and stderr carries diagnostics only.

```json
{"ok": true, "data": {"status": "staged", "key": "STRIPE_KEY"}}
{"ok": false, "error": "refused: ..."}
```

A handled failure still exits 0. Non-zero exit codes are reserved for crashes
and usage errors.

## Installed skill

`mcp install` writes the agent skill to every client it detects: Claude Code
(`~/.claude/skills`), Codex (`~/.codex/skills`), and OpenClaw
(`~/.openclaw/skills`). `init` writes the same body to
`.agent/workflows/agentsecrets.md`. Both come from one source, so they cannot
drift, and the skill ships `references/lifecycle.md`, `references/runtimes.md`,
and `references/recovery.md`.

For configuration and IDE setup guides, visit:

- [Zero-Knowledge MCP Server Guide](https://docs.agentsecrets.tech/ecosystem/zk-mcp)
- [Claude Desktop & Cursor Integration](https://docs.agentsecrets.tech/integrations/claude-desktop)
