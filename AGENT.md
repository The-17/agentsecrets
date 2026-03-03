# AGENT.md

This file tells AI agents how to work with this repository.

AgentSecrets is zero-knowledge secrets infrastructure for AI agents. If you are an AI agent reading this file, you are likely here to contribute to the codebase, understand the architecture, or help a developer work with this project.

---

## What AgentSecrets Is

AgentSecrets is the secrets layer for the agentic era. It solves a specific problem: AI agents need to make authenticated API calls, but giving agents credential values creates an attack surface — prompt injection, malicious plugins, and compromised extensions can all reach values held in agent memory.

AgentSecrets removes credential values from the agent's context entirely. The agent operates the credential lifecycle — status checks, drift detection, syncing, calling APIs, auditing — without ever seeing a value.

**The agent operates it. The agent never sees it.**

---

## Repository Structure

```
agentsecrets/
├── cmd/agentsecrets/
│   ├── main.go                    # Entry point
│   └── commands/                  # All CLI commands
│       ├── root.go                # Root command + middleware
│       ├── init.go                # Account creation
│       ├── login.go               # Account login
│       ├── logout.go              # Clear session
│       ├── status.go              # Current context
│       ├── workspace.go           # Workspace management
│       ├── allowlist.go           # Zero-trust domain allowlist
│       ├── project.go             # Project management
│       ├── secrets.go             # Secrets CRUD + sync
│       ├── proxy.go               # HTTP proxy + logs
│       ├── call.go                # One-shot authenticated calls
│       ├── env.go                 # Env var injection into child processes
│       ├── mcp.go                 # MCP server + install
│       └── exec.go                # OpenClaw exec provider
├── pkg/
│   ├── api/                       # HTTP API client
│   ├── auth/                      # Authentication + JWT middleware
│   ├── config/                    # Global config + project config
│   ├── crypto/                    # X25519 + AES-256-GCM + Argon2id
│   ├── keyring/                   # OS keychain integration
│   ├── mcp/                       # MCP server implementation
│   ├── projects/                  # Project API wrappers
│   ├── proxy/                     # HTTP proxy + audit logging
│   ├── secrets/                   # Secret management + dotenv
│   ├── ui/                        # Terminal UI components
│   └── workspaces/                # Workspace API wrappers
├── integrations/
│   └── openclaw/                  # OpenClaw skill
│       └── SKILL.md
├── docs/
│   ├── API_SPECIFICATION.md       
│   ├── ARCHITECTURE.md            
│   ├── CONTRIBUTING.md            
│   ├── DEMO_SCRIPT.md             
│   ├── PROXY.md                   
│   ├── QUICKSTART.md              
│   ├── commands/                  # Command reference docs
│   └── learning/                  # Tutorials and guides
└── .agent/
    └── workflows/
        └── agentsecrets.md        # Operational workflow for AI agents
```

---

## Architecture

### Security Model

| Layer | Implementation |
|---|---|
| Key exchange | X25519 (NaCl SealedBox) |
| Secret encryption | AES-256-GCM |
| Key derivation | Argon2id |
| Key storage | OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) |
| Transport | HTTPS / TLS |
| Cloud server | Zero-knowledge — stores encrypted blobs, cannot decrypt |
| Proxy | Session token, SSRF protection, redirect stripping |
| Audit log | No value field in struct — structurally cannot log credential values |

### Zero-Knowledge Guarantee

The zero-knowledge guarantee is architectural, not policy-based. At every step in the system:

- `secrets list` returns key names only
- `secrets diff` returns sync status only
- `secrets pull` writes values to OS keychain — not to any variable or file
- `agentsecrets call` sends key name to proxy — proxy resolves from keychain, injects at transport layer, returns API response only
- `agentsecrets env` injects keychain values into child process environment — values never enter the calling process or any log
- `proxy logs` records key name, endpoint, status code, duration — no value field exists in the struct

There is no code path that puts a credential value into agent context.

### Zero-Trust Proxy Enforcement

The proxy enforces a **deny-by-default** security posture:

- **Domain Allowlist:** Every outbound request must target a domain explicitly authorized in the workspace allowlist. Unauthorized domains are blocked with 403 Forbidden.
- **Response Body Redaction:** If an external API echoes back the injected credential in its response, the proxy replaces the value with `[REDACTED_BY_AGENTSECRETS]` before returning it. The audit log records the event with reason `credential_echo`.
- **Admin-Only Allowlist:** Only workspace admins can modify the allowlist (requires password verification). Use `agentsecrets workspace promote/demote` to manage roles.

### Storage Modes

- `StorageMode 0` — standard local dev (reads/writes `.env`)
- `StorageMode 1` — keychain only (writes `.env.example` with key names, values go to OS keychain)

Keychain mode is the secure default for production use.

---

## Building and Running

```bash
# Clone
git clone https://github.com/The-17/agentsecrets
cd agentsecrets

# Install dependencies
go mod download

# Build
make build
# or
go build -o agentsecrets ./cmd/agentsecrets

# Run tests
make test
# or
go test ./...

# Run locally
go run ./cmd/agentsecrets/main.go
```

---

## Key Packages

### `pkg/keyring`

OS keychain integration. All credential values are stored and retrieved here. Every secret operation that touches a value goes through this package.

Key functions:
- `GetSecret(projectID, keyName)` — retrieve value from keychain
- `SetSecret(projectID, keyName, value)` — store value in keychain
- `DeleteSecret(projectID, keyName)` — remove from keychain
- `GetAllProjectSecrets(projectID)` — list all secrets for a project as a map

### `pkg/crypto`

Encryption primitives. X25519 key exchange, AES-256-GCM encryption, Argon2id key derivation. Used for client-side encryption before cloud upload.

### `pkg/config`

Global config at `~/.agentsecrets/config.json` — stores active workspace, auth tokens, storage mode. Project config stored per-directory.

### `pkg/auth/middleware.go`

`EnsureAuth` — Cobra PersistentPreRunE middleware. Runs before every authenticated command. Checks token expiry, silently refreshes if expired or expiring within 5 minutes.

### `pkg/proxy`

HTTP proxy implementation. Handles the 6 auth injection styles, domain allowlist enforcement, response body redaction, SSRF protection, redirect stripping, session token validation, JSONL audit logging.

---

## CLI Command Surface

### Account
```bash
agentsecrets init [--storage-mode 0|1]
agentsecrets login
agentsecrets logout
agentsecrets status
```

### Workspaces
```bash
agentsecrets workspace create "Name"
agentsecrets workspace list
agentsecrets workspace switch "Name"
agentsecrets workspace invite user@email.com
agentsecrets workspace promote user@email.com   # Grant admin role
agentsecrets workspace demote user@email.com     # Revoke admin role
```

### Workspace Allowlist
```bash
agentsecrets workspace allowlist add <domain> [domain...]  # Authorize domains
agentsecrets workspace allowlist list                      # List allowed domains
agentsecrets workspace allowlist log                       # View allowlist audit log
```

### Projects
```bash
agentsecrets project create NAME
agentsecrets project list
agentsecrets project use NAME
agentsecrets project update NAME
agentsecrets project delete NAME
```

### Secrets
```bash
agentsecrets secrets set KEY=value
agentsecrets secrets get KEY
agentsecrets secrets list [--project NAME]
agentsecrets secrets push
agentsecrets secrets pull
agentsecrets secrets delete KEY
agentsecrets secrets diff
```

### Proxy and Calls
```bash
agentsecrets call --url URL --bearer KEY
agentsecrets call --url URL --method POST --bearer KEY --body '{}'
agentsecrets call --url URL --header Name=KEY
agentsecrets call --url URL --query param=KEY
agentsecrets call --url URL --basic KEY
agentsecrets call --url URL --body-field path=KEY
agentsecrets call --url URL --form-field field=KEY
agentsecrets proxy start [--port 8765]
agentsecrets proxy status
agentsecrets proxy stop
agentsecrets proxy logs [--last N] [--secret KEY]
agentsecrets exec
agentsecrets mcp serve
agentsecrets mcp install
```

### Environment Injection
```bash
agentsecrets env -- <command> [args...]  # Inject secrets as env vars into child process
agentsecrets env -- stripe mcp           # Wrap Stripe MCP
agentsecrets env -- node server.js       # Wrap Node.js
```

---

## Contributing Guidelines

### Adding a New Command

1. Create a new file in `cmd/agentsecrets/commands/`
2. Define a `NewXxxCmd()` function returning `*cobra.Command`
3. Register in `root.go` with `rootCmd.AddCommand(NewXxxCmd())`
4. Add `EnsureAuth` as PersistentPreRunE if the command requires authentication
5. Use `pkg/keyring` for any credential operations — never handle raw values in command layer
6. Write nothing credential-related to stdout — use stderr for errors only

### Security Rules for Contributors

- Never log credential values anywhere — not stdout, not stderr, not files
- Never pass credential values as function arguments where avoidable — pass key names and resolve at the last possible moment via keyring
- Never write credential values to any file — keychain only for StorageMode 1
- The audit log struct must never gain a value field
- All new cloud sync operations must use the existing crypto package — no plaintext uploads

### Testing

```bash
go test ./...
go test ./pkg/keyring/...
go test ./pkg/crypto/...
go test ./pkg/proxy/...
```

---

## Integration Points

### MCP (Claude Desktop + Cursor)

AgentSecrets runs as an MCP server exposing `api_call` and `list_secrets` tools. Config auto-written to `~/.cursor/mcp.json` and `~/Library/Application Support/Claude/claude_desktop_config.json` by `agentsecrets mcp install`.

### OpenClaw Exec Provider

`agentsecrets exec` implements the OpenClaw SecretRef exec provider protocol (v2026.2.26). Reads JSON from stdin, resolves from `OPENCLAW_MANAGER` project in active workspace, writes JSON to stdout. See `cmd/agentsecrets/commands/exec.go`.

### HTTP Proxy

Any agent or framework that makes HTTP requests can use the proxy at `localhost:8765`. Send `X-AS-Target-URL` and `X-AS-Inject-Bearer` (or other auth style headers) — proxy resolves, injects, forwards, returns response.

### Workflow File

`.agent/workflows/agentsecrets.md` is written to the project directory on `agentsecrets init`. Any AI assistant that reads workflow files picks up the full operational instructions automatically.

### Environment Variable Injection

`agentsecrets env -- <command>` injects all secrets from the active project's keychain into a child process as environment variables. Secrets exist only in the child process memory — nothing is written to disk. Use for wrapping CLI tools like Stripe, or running dev servers that read from env vars.

```bash
agentsecrets env -- stripe mcp
agentsecrets env -- node server.js
```

---

## Links

- GitHub: https://github.com/The-17/agentsecrets
- ClawHub: https://clawhub.ai/SteppaCodes/agentsecrets
- Security issues: hello@theseventeen.co (do not open public issues)