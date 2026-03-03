# agentsecrets env

> Inject secrets as environment variables into a child process.

## Usage

```bash
agentsecrets env -- <command> [args...]
```

## Description

Resolves all secrets from the active project in the OS keychain and injects them as environment variables into the specified command. The command runs with secrets available as env vars. Nothing is written to disk. Secrets exist only in the child process memory.

When the child process exits, the secrets are gone.

## Examples

```bash
# Wrap Stripe CLI
agentsecrets env -- stripe mcp
agentsecrets env -- stripe listen --forward-to localhost:3000

# Wrap Node.js
agentsecrets env -- node server.js

# Wrap any dev server
agentsecrets env -- npm run dev

# Check a secret is available
agentsecrets env -- printenv STRIPE_KEY
```

## How It Works

1. Loads the active project from `.agentsecrets/project.json`
2. Calls `keyring.GetAllProjectSecrets()` to resolve all secrets from the OS keychain
3. Builds environment: parent process env + injected secrets (secrets override on conflict)
4. Spawns child process via `exec.Command` with `stdin`, `stdout`, `stderr` wired through
5. Forwards `SIGINT` / `SIGTERM` signals to the child process
6. Exits with the child's exit code (transparent passthrough)
7. Logs key names (never values) to the audit log with method `ENV`

## Claude Desktop Config

Wrap native MCP servers with AgentSecrets env injection:

```json
{
  "mcpServers": {
    "stripe": {
      "command": "agentsecrets",
      "args": ["env", "--", "stripe", "mcp"]
    }
  }
}
```

## Output

```
ℹ Injecting 9 secrets: STRIPE_KEY + 8 more
```

For a single secret:
```
ℹ Injecting 1 secret: STRIPE_KEY
```

## Audit Log

The env command logs an audit event with:
- `method`: `ENV`
- `secret_keys`: array of injected key names
- `target_url`: the command that was run
- `auth_styles`: `["env_inject"]`

No secret values are ever logged.

## Security

- Secrets exist only in child process memory — not written to disk at any point
- The calling process never accesses secret values (they go directly from keychain to child env)
- If the child process is terminated, the secrets are immediately gone
- Audit log records key names only — structurally cannot log values
