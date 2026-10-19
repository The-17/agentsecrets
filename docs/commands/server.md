# agentsecrets server

> View, set, test, and reset the target AgentSecrets server endpoint.

## Usage

```bash
agentsecrets server get
agentsecrets server set <URL> [--project] [--force]
agentsecrets server status
agentsecrets server reset [--project]
```

## Description

The `server` command group allows you to manage where the AgentSecrets CLI sends API requests.

By default, AgentSecrets communicates with the official default AgentSecrets Server (`https://api.agentsecrets.tech/api`).
When deploying an open-source self-hosted AgentSecrets server, you can point your local CLI to your custom instance globally or for a specific repository.

## Subcommands

### `agentsecrets server get`

Displays the active server endpoint, its configuration source, and whether the server is the default or self-hosted instance.

```bash
agentsecrets server get
```

Output:
```
AgentSecrets Server Target
  ──────────────────────────────
  Target Type:                   AgentSecrets Server (Default)
  API Endpoint:                  https://api.agentsecrets.tech/api
  Config Source:                 AgentSecrets Server (default)
```

Aliases: `agentsecrets server show`, `agentsecrets server`

---

### `agentsecrets server set <URL>`

Sets the target server URL and verifies reachability via an HTTP ping.

```bash
# Global configuration (stored in ~/.agentsecrets/config.json)
agentsecrets server set http://localhost:8000

# Project-specific override (stored in .agentsecrets/project.json)
agentsecrets server set https://api.agentsecrets.internal.corp --project

# Skip connectivity verification
agentsecrets server set http://localhost:8000 --force
```

---

### `agentsecrets server status`

Tests connectivity and latency to the active server endpoint.

```bash
agentsecrets server status
```

Output:
```
Server Connection Status
  ──────────────────────────────
  Server Type:                   AgentSecrets Server (Default)
  Endpoint:                      https://api.agentsecrets.tech/api
  Config Source:                 AgentSecrets Server (default)
  Status:                        ONLINE
  Latency:                       42ms
```

---

### `agentsecrets server reset`

Restores the target server back to the default AgentSecrets Server.

```bash
# Reset global setting
agentsecrets server reset

# Reset project override
agentsecrets server reset --project
```

## Resolution Priority

When executing any CLI command, the active server is resolved in the following order:

1. CLI Flag (`--server <URL>`)
2. Environment Variable (`AGENTSECRETS_SERVER_URL` or `AGENTSECRETS_API_URL`)
3. Project Config (`.agentsecrets/project.json`)
4. Global Config (`~/.agentsecrets/config.json`)
5. Default Server (`https://api.agentsecrets.tech/api`)

---

## Official Documentation

For complete server deployment and self-hosting guides, visit:
👉 **[Server & Self-Hosting Guide](https://docs.agentsecrets.tech/cli/server)**
👉 **[Self-Hosting Deployment Architecture](https://docs.agentsecrets.tech/api/self-hosting)**
