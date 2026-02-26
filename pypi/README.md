# AgentSecrets

> **Your AI agent has root access to your API keys. Fix that.**

30,000+ OpenClaw installations compromised. API keys stolen from plaintext `.env` files. The problem isn't OpenClaw — it's every AI agent framework. They all store credentials where any plugin, any skill, any process can read them.

AgentSecrets is a **zero-knowledge credential proxy**. Your agent makes authenticated API calls without ever seeing the actual key values.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://go.dev/)

---

## How It Works

```
Your Agent                    AgentSecrets                 Upstream API
    |                              |                            |
    |-- "use STRIPE_KEY" --------->|                            |
    |                              |-- OS keychain lookup ----->|
    |                              |<-- real key value ---------|
    |                              |                            |
    |                              |-- inject into request ---->|
    |                              |-- forward to API --------->|
    |                              |<-- API response -----------|
    |                              |                            |
    |<-- response only ------------|                            |
    |                              |                            |
    |  Never sees: sk_test_51H...  |                            |
```

Your agent says **"use STRIPE_KEY"**. AgentSecrets resolves the real value from your OS keychain, injects it into the HTTP request, and returns only the response. The key value never enters agent memory, never appears in chat logs, never touches the filesystem.

---

## Installation

**macOS / Linux (One-liner):**
```bash
curl -sSL https://get.agentsecrets.com | sh
```

**Homebrew:**
```bash
brew install The-17/tap/agentsecrets
```

**Python (pip):**
```bash
pip install agentsecrets
```

**Go (source):**
```bash
go install github.com/The-17/agentsecrets/cmd/agentsecrets@latest
```

---

## Quick Start

# Create account + encryption keys
agentsecrets init

# Create a project (secrets are organized by project)
agentsecrets project create my-app

# Store your API keys in the OS keychain
agentsecrets secrets set STRIPE_KEY=sk_test_51Hxxxxx
agentsecrets secrets set OPENAI_KEY=sk-proj-xxxxxxx

# Make an authenticated API call (agent never sees the key)
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY
```

---

## Why You Need This

### Before AgentSecrets
```
~/.openclaw/.env              ← plaintext, readable by any process
~/.openclaw/openclaw.json     ← plaintext
Agent memory & chat logs      ← keys persist after use
```
A malicious skill, an infostealer, or a single RCE = **all your keys compromised**.

### With AgentSecrets
```
OS Keychain (encrypted)       ← protected by system authentication
Agent sees key NAMES only     ← "STRIPE_KEY", never "sk_test_51H..."
Full audit trail              ← who used what, when (names only, never values)
```
A malicious skill can't steal what it never sees.

| | Default (`.env`) | With AgentSecrets |
|---|---|---|
| Storage | Plaintext files | OS keychain (encrypted) |
| Agent sees values | ✅ Yes | ❌ Never |
| Malicious plugin risk | Can read all keys | Nothing to steal |
| Chat log exposure | Possible | Impossible |
| Audit trail | None | Full JSONL log |
| Breach impact | All keys exposed | Keys safe |

---

## 6 Auth Styles — Every API Covered

```bash
# Bearer token (Stripe, OpenAI, GitHub)
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY

# Custom header (SendGrid, AWS Gateway)
agentsecrets call --url https://api.sendgrid.com/v3/mail/send --header X-Api-Key=SENDGRID_KEY

# Query parameter (Google Maps, weather APIs)
agentsecrets call --url "https://maps.googleapis.com/maps/api/geocode/json" --query key=GMAP_KEY

# Basic auth (Jira, legacy REST)
agentsecrets call --url https://jira.example.com/rest/api/2/issue --basic JIRA_CREDS

# JSON body injection
agentsecrets call --url https://api.example.com/auth --body-field client_secret=SECRET

# Form field injection
agentsecrets call --url https://oauth.example.com/token --form-field api_key=KEY
```

Combine multiple credentials in one call:
```bash
agentsecrets call --url https://api.example.com/data --bearer AUTH_TOKEN --header X-Org-ID=ORG_SECRET
```

---

## Integrations

### OpenClaw

Set up a dedicated project to store all your OpenClaw credentials:

```bash
# One-time setup
pip install agentsecrets
agentsecrets init
agentsecrets project create OPENCLAW_MANAGER
agentsecrets secrets set STRIPE_KEY=sk_test_xxx
agentsecrets secrets set OPENAI_KEY=sk-proj-xxx
```

Install the skill:
```bash
# From ClawHub (when available)
openclaw skill install agentsecrets

# Or manual install
cp -r integrations/openclaw ~/.openclaw/skills/agentsecrets
```

Then just ask your agent:
> "Check my Stripe balance"

The agent runs `agentsecrets call --bearer STRIPE_KEY` under the hood. You see the balance. The agent never sees `sk_test_51H...`.

### Claude Desktop & Cursor (MCP)

Auto-configure with one command:
```bash
agentsecrets mcp install
```

Or add manually to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "agentsecrets": {
      "command": "/path/to/agentsecrets",
      "args": ["mcp", "serve"]
    }
  }
}
```

Ask Claude: *"Check my Stripe balance"* → uses `api_call` tool → you see the response, Claude never sees the key.

### HTTP Proxy (Any Agent)

For agents that run shell commands or make HTTP requests:

```bash
# Start proxy
agentsecrets proxy start

# Agent sends requests with injection headers
curl http://localhost:8765/proxy \
  -H "X-AS-Target-URL: https://api.stripe.com/v1/balance" \
  -H "X-AS-Inject-Bearer: STRIPE_KEY"
```

See [PROXY.md](docs/PROXY.md) for the full proxy reference.

### AI Workflow File

`agentsecrets init` creates a `.agent/workflows/api-call.md` that teaches any AI assistant (Gemini, Copilot, etc.) how to use AgentSecrets automatically.

---

## Audit Trail

Every proxied call is logged. Key **names** only — never values:

```bash
agentsecrets proxy logs --last 5
```

```
Time      Method  Target URL                              Secrets     Auth    Status  Duration
01:15:00  GET     https://api.stripe.com/v1/balance       STRIPE_KEY  bearer  200     245ms
01:16:30  POST    https://api.openai.com/v1/chat/...      OPENAI_KEY  bearer  200     1203ms
```

The log struct has no field for values — it's structurally impossible to log them.

---

## Full Command Reference

### Account
```bash
agentsecrets init                            # Create account or login
agentsecrets login                           # Login to existing account
agentsecrets logout                          # Clear session
agentsecrets status                          # Show session info
```

### Workspaces & Projects
```bash
agentsecrets workspace list                  # List workspaces
agentsecrets workspace create "Team Name"    # Create workspace
agentsecrets workspace switch "Team Name"    # Switch workspace
agentsecrets workspace invite user@email.com # Invite teammate

agentsecrets project create my-app           # Create project
agentsecrets project list                    # List projects
agentsecrets project use my-app              # Select project
```

### Secrets
```bash
agentsecrets secrets set KEY=value           # Store a secret
agentsecrets secrets get KEY                 # Retrieve a secret
agentsecrets secrets list                    # List key names
agentsecrets secrets push                    # Upload local .env to cloud
agentsecrets secrets pull                    # Download cloud secrets to .env
agentsecrets secrets delete KEY              # Remove a secret
agentsecrets secrets diff                    # Compare local vs cloud
```

### Credential Proxy
```bash
agentsecrets call --url <URL> --bearer KEY   # One-shot authenticated call
agentsecrets proxy start [--port 8765]       # Start HTTP proxy
agentsecrets proxy status                    # Check proxy
agentsecrets proxy logs [--last N]           # View audit log
agentsecrets mcp serve                       # Start MCP server
agentsecrets mcp install                     # Auto-configure AI tools
```

---

## Security Model

| Layer | Implementation |
|-------|---------------|
| Key exchange | X25519 (NaCl SealedBox) |
| Secret encryption | AES-256-GCM |
| Key derivation | Argon2id |
| Key storage | OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) |
| Transport | HTTPS / TLS |
| Server | Zero-knowledge — stores encrypted blobs only |

- Secrets encrypted **client-side** before upload
- Private keys never leave your OS keychain
- Server can't decrypt your secrets (by design)
- Audit logs record key **names**, never **values**

### Reporting Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.  
Email: hello@theseventeen.co — we respond within 24 hours.

---

## Development

**Status**: Alpha / Active Development  
**Stability**: API stable, may add features  

```bash
# Clone and build
git clone https://github.com/The-17/agentsecrets
cd agentsecrets
go mod download
make build

# Run tests
make test

# Format + lint + test
make pre-commit
```

### Roadmap

- [x] Core CLI (10 commands)
- [x] Proxy Engine (6 auth styles)
- [x] MCP Server (Claude Desktop, Cursor)
- [x] HTTP Proxy Server
- [x] OpenClaw Integration
- [x] Audit Logging
- [ ] Multi-platform release binaries
- [ ] Web dashboard
- [ ] Secret rotation
- [ ] 1Password / Vault import
- [ ] 1.0 release

---

## FAQ

**How is this different from `.env` files?**  
`.env` files are plaintext on disk. Any process can read them. AgentSecrets stores keys in your OS keychain (encrypted, system-protected) and injects them at request time.

**Can I use this without AI?**  
Yes. `agentsecrets call` is useful for any developer who wants to make API calls without credentials in shell history.

**What if the server gets hacked?**  
Your secrets are safe. The server only stores encrypted blobs it can't read. Your decryption key is in your OS keychain, not on the server.

**Does it work with [language]?**  
Yes. AgentSecrets is a standalone CLI binary that works with any language, framework, or deployment tool.

**What about Docker?**  
Docker isolates your agent but your keys are still plaintext *inside* the container. AgentSecrets fixes the root cause: agents should never have access to key values at all.

---

## Links

- [Architecture](docs/ARCHITECTURE.md) — deep dive into the security model
- [Proxy Reference](docs/PROXY.md) — full HTTP proxy documentation
- [Contributing](docs/CONTRIBUTING.md) — how to help
- [Quick Start](docs/QUICKSTART.md) — detailed setup guide

---

## License

MIT License — see [LICENSE](LICENSE)

---

Built by [The Seventeen](https://github.com/The-17)

**Your keys deserve better than a plaintext file.** ⭐