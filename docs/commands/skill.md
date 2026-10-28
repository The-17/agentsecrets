# agentsecrets skill

> Print or install the agent skill, for any AI client.

## Usage

```bash
# Print SKILL.md to stdout
agentsecrets skill

# Print SKILL.md plus references/, separated by headers
agentsecrets skill --all

# Print just the version
agentsecrets skill --version

# Write SKILL.md and references/ into a directory
agentsecrets skill --dir ~/.windsurf/skills/agentsecrets
```

## When to use it

`agentsecrets mcp install` covers the clients we know: it configures the MCP
server for Claude Desktop and Cursor, and installs the skill for Claude Code,
Codex, and OpenClaw.

Use `agentsecrets skill` for everything else. It emits the same bytes the native
installers write, so any agent that reads a markdown instruction file or a
skills directory can use it:

```bash
# An agent with a skills directory
agentsecrets skill --dir ~/.myagent/skills/agentsecrets

# An agent that reads a single instruction file
agentsecrets skill > AGENTS.md

# A project, checked in with the repo
agentsecrets skill --dir .agent/skills/agentsecrets
```

Keep `references/` beside `SKILL.md`: the body is the loop, the references carry
the lifecycle steps, the runtime differences, and the recovery paths.

## What it writes

| Path | Contents |
| --- | --- |
| `SKILL.md` | The loop and the rules: what the agent may do alone, what it must hand to a human, how to call an API without holding a value |
| `references/lifecycle.md` | The eight credential steps and who owns each |
| `references/runtimes.md` | Local versus cloud, and how to tell which one you are in |
| `references/recovery.md` | Failure modes, diagnosis, and hand-off |

## Flags

| Flag | Meaning |
| --- | --- |
| `--all` | Print SKILL.md and every reference file, separated by headers |
| `--version` | Print only the skill version (matches the CLI that generated it) |
| `--dir <path>` | Write SKILL.md and `references/` into `<path>` instead of printing |

See [The agent skill](../skill.md) for the placement table and the rules that
make a copied skill work.
