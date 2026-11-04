# The agent skill

> One procedure, every agent. Install it natively where we support the client, or copy it anywhere else.

## What the skill is

Tools make management possible. They do not make an agent competent. The skill is
the procedure: it tells an agent to operate credentials that already exist —
read, diff, sync, audit, verify — and to hand every irreversible action back to
you with the exact command to run.

It is versioned with the product, so the copy on your machine matches the binary
that wrote it:

```bash
agentsecrets skill --version
```

## Get it

```bash
agentsecrets skill                    # SKILL.md to stdout
agentsecrets skill --all              # SKILL.md plus references/, separated by headers
agentsecrets skill --dir <path>       # write SKILL.md + references/ into a directory
```

`agentsecrets mcp install` does this for the clients below and also configures
the MCP server. Use `agentsecrets skill` when your agent is not in the table, or
when you want the text in front of you.

## Where it goes

| Client | How to install | Where it lands |
| --- | --- | --- |
| Claude Code | `agentsecrets mcp install` | `~/.claude/skills/agentsecrets/` |
| Codex | `agentsecrets mcp install` | `~/.codex/skills/agentsecrets/` |
| OpenClaw | `agentsecrets mcp install` | `~/.openclaw/skills/agentsecrets/` |
| Claude Desktop | `agentsecrets mcp install` | MCP config only (no skill directory) |
| Cursor | `agentsecrets mcp install` | MCP config only (no skill directory) |
| Windsurf, Cline, and others | `agentsecrets skill --dir ~/.windsurf/skills/agentsecrets` | the directory you name |
| Anything that reads a markdown instruction file | `agentsecrets skill > path/to/AGENTS.md` | the file you name |
| A project, not a machine | `agentsecrets skill --dir .agent/skills/agentsecrets` | checked in with the repo |

Two rules that make the copy work:

1. **Point the agent at the file, not at a summary of it.** The skill only works
   if it is loaded as instructions on every session.
2. **Keep `references/` next to `SKILL.md`.** The body is the loop; the
   references carry the lifecycle steps, the runtime differences, and the
   recovery paths. Copying one without the other gives an agent a map with no
   legend.

## What is inside

- **`SKILL.md`** — the loop and the rules: what the agent may do alone, what it
  must hand to you, and how to make an authenticated call without ever holding a
  value.
- **`references/lifecycle.md`** — the eight credential steps, with the agent's
  share and the human's share of each.
- **`references/runtimes.md`** — local versus cloud: which one you are in, what
  changes, and what does not.
- **`references/recovery.md`** — the failure modes a fresh agent actually hits,
  with the diagnosis and the hand-off for each.

## Pair it with the MCP server

The skill tells an agent *how* to act. The MCP server gives it *what* to act
with. Together:

```bash
agentsecrets mcp install      # server config + skill for the clients we know
agentsecrets skill --dir ...  # skill only, for any other agent
```

See [agentsecrets mcp](commands/mcp.md) for the tool surface and the write
switch.

## Keeping a copy honest

If you vendor the skill into your own repo, pin the version and regenerate on
upgrade:

```bash
agentsecrets skill --version
agentsecrets skill --dir .agent/skills/agentsecrets
```

A stale copy is worse than none: it teaches a command the binary no longer has.
The AgentSecrets repo guards its own vendored copies with a test that resolves
every documented command against the real CLI.
