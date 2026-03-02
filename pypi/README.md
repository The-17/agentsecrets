# AgentSecrets

> **Zero-knowledge secrets infrastructure built for AI agents to operate, not just consume.**

Every other secrets tool was built for humans to provision credentials to agents. AgentSecrets was built for agents to manage credentials themselves — without ever seeing a single value.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)
[![ClawHub](https://img.shields.io/badge/ClawHub-agentsecrets-blue)](https://clawhub.ai/SteppaCodes/agentsecrets)

---

## What This Is

Most secrets tools treat AI agents as consumers — something that receives a credential and uses it. AgentSecrets treats the agent as an operator.

Your agent checks its own status. Notices a secret is out of sync. Pulls the latest from the cloud. Makes the authenticated API call. Audits what it did. All of this without ever knowing a single credential value.

```bash
# An AI agent managing its own secrets workflow autonomously

agentsecrets status               # what workspace, project, last sync?
agentsecrets secrets diff         # anything out of sync?
agentsecrets secrets pull         # sync from cloud to keychain
agentsecrets secrets list         # what keys are available?
agentsecrets call \
  --url https://api.stripe.com/v1/balance \
  --bearer STRIPE_KEY             # make the authenticated call
agentsecrets proxy logs           # audit what just happened
```

The agent ran the entire credentials workflow. It never saw `sk_live_51H...`. Not at any step.

This is what it means to be built for the agentic era — not bolted onto it.

---

## The Problem With Every Other Approach

Traditional vaults protect credentials at rest. Once an agent retrieves a key to use it, that key is in agent memory. That's where it gets vulnerable.

```
Vault → agent retrieves sk_live_51H... → key is in agent memory
                                        → prompt injection can reach it
                                        → malicious plugin can reach it  
                                        → CVE can expose it
```

AgentSecrets never puts the value in agent memory. The proxy resolves from the OS keychain and injects at the transport layer. The agent makes the call. It sees only the response.

```
AgentSecrets → agent says "use STRIPE_KEY" → proxy resolves from OS keychain
                                           → injects into HTTP request
                                           → returns API response only
                                           → value never entered agent context
```

You cannot steal what was never there.

---

## Installation

**pip:**
```bash
pip install agentsecrets
```

---

## Quick Start

```bash
# Create account + encryption keys
agentsecrets init

# Create a project
agentsecrets project create my-app

# Store credentials — values go to OS keychain, never to disk
agentsecrets secrets set STRIPE_KEY=sk_live_51H...
agentsecrets secrets set OPENAI_KEY=sk-proj-...
agentsecrets secrets set DATABASE_URL=postgresql://...

# Or push your existing .env all at once
agentsecrets secrets push

# Connect your AI tool
npx @the-17/agentsecrets mcp install   # Claude Desktop + Cursor
agentsecrets proxy start               # Any agent via HTTP
openclaw skill install agentsecrets    # OpenClaw
```

Your agent now has full API access. It will never see a credential value.

---

## The Agent Workflow

This is what AgentSecrets looks like when an AI agent is operating it end to end.

### Check status
```bash
agentsecrets status
# Logged in as: steppa@theseventeen.co
# Workspace:    Acme Engineering
# Project:      payments-service
# Last pull:    2 minutes ago
```

### Notice drift and sync
```bash
agentsecrets secrets diff
# LOCAL ONLY:  PAYSTACK_KEY
# REMOTE ONLY: SENDGRID_KEY
# OUT OF SYNC: STRIPE_KEY (remote is newer)

agentsecrets secrets pull
# Synced 3 secrets from cloud to OS keychain
```

### Make authenticated calls
```bash
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY
# {"object":"balance","available":[{"amount":420000,"currency":"usd"}]}
```

### Audit what happened
```bash
agentsecrets proxy logs --last 10
# 14:23:01  GET  api.stripe.com/v1/balance   STRIPE_KEY  200  245ms
# 14:31:15  POST api.stripe.com/v1/charges   STRIPE_KEY  200  412ms
# 14:31:16  POST api.openai.com/v1/chat/...  OPENAI_KEY  200  1203ms
```

The agent managed the complete credentials lifecycle. No human touched the workflow. No credential value was exposed at any step.

---

## Zero-Knowledge Architecture

AgentSecrets is zero-knowledge at every layer — not just at the point of API injection.

| Step | What the agent sees |
|---|---|
| `secrets list` | Key names only |
| `secrets diff` | Key names and sync status |
| `secrets pull` | Confirmation message — values go to OS keychain |
| `agentsecrets call` | API response only |
| `proxy logs` | Key names, endpoints, status codes |

The log struct has no value field. It is structurally impossible to accidentally log a credential value anywhere in the system.

### Encryption
| Layer | Implementation |
|---|---|
| Key exchange | X25519 (NaCl SealedBox) |
| Secret encryption | AES-256-GCM |
| Key derivation | Argon2id |
| Key storage | OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) |
| Transport | HTTPS / TLS |
| Server | Stores encrypted blobs only — cannot decrypt |
| Proxy | Session token, SSRF protection, redirect stripping |

---

## Team Workspaces

AgentSecrets is built for teams. A workspace is a shared environment — teammates join and get access to projects within it. Secrets are encrypted client-side before upload. The server cannot decrypt them.

```bash
# Create workspace
agentsecrets workspace create "Acme Engineering"

# Invite teammates
agentsecrets workspace invite alice@acme.com
agentsecrets workspace invite bob@acme.com

# Partition by service
agentsecrets project create payments-service
agentsecrets project create auth-service
agentsecrets project create data-pipeline
```

**New developer onboards:**
```bash
agentsecrets login
agentsecrets workspace switch "Acme Engineering"
agentsecrets project use payments-service
agentsecrets secrets pull
# Ready. No credential sharing. No .env files sent over Slack.
```

Every AI agent every teammate runs has access to the credentials it needs. None of them ever see the values.

---

## The Credential Proxy

AgentSecrets runs a local HTTP proxy on `localhost:8765`. Agents send requests with injection headers. The proxy resolves from the OS keychain, injects into the outbound request, returns only the response.

### 6 Auth Styles

```bash
# Bearer token (Stripe, OpenAI, GitHub, most modern APIs)
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY

# Custom header (SendGrid, Twilio, API Gateway)
agentsecrets call --url https://api.sendgrid.com/v3/mail/send \
  --header X-Api-Key=SENDGRID_KEY

# Query parameter (Google Maps, weather APIs)
agentsecrets call --url "https://maps.googleapis.com/maps/api/geocode/json" \
  --query key=GMAP_KEY

# Basic auth (Jira, legacy REST APIs)
agentsecrets call --url https://jira.example.com/rest/api/2/issue \
  --basic JIRA_CREDS

# JSON body injection
agentsecrets call --url https://api.example.com/auth \
  --body-field client_secret=SECRET

# Form field injection
agentsecrets call --url https://oauth.example.com/token \
  --form-field api_key=KEY
```

---

## AI Tool Integrations

### Claude Desktop + Cursor (MCP)

```bash
npx @the-17/agentsecrets mcp install
```

Auto-configures your MCP setup. No credential values in any config file.

```json
{
  "mcpServers": {
    "agentsecrets": {
      "command": "/usr/local/bin/agentsecrets",
      "args": ["mcp", "serve"]
    }
  }
}
```

### OpenClaw (Skill + Exec Provider)

```bash
openclaw skill install agentsecrets
```

AgentSecrets ships as both a ClawHub skill and a native exec provider for OpenClaw's SecretRef system (shipped in v2026.2.26). The agent manages the full secrets workflow autonomously within OpenClaw.

### Any AI Assistant (Workflow File)

`agentsecrets init` creates `.agent/workflows/api-call.md` — a workflow file that teaches any AI assistant how to use AgentSecrets automatically. Claude, Gemini, Copilot, or any tool that reads workflow files picks it up without configuration.

### HTTP Proxy (Any Agent or Framework)

```bash
agentsecrets proxy start

curl http://localhost:8765/proxy \
  -H "X-AS-Target-URL: https://api.stripe.com/v1/charges" \
  -H "X-AS-Inject-Bearer: STRIPE_KEY"
```

Works with LangChain, CrewAI, AutoGen, and any agent that makes HTTP requests.

---

## Full Command Reference

### Account
```bash
agentsecrets init                    # Create account or login
agentsecrets login                   # Login to existing account
agentsecrets logout                  # Clear session
agentsecrets status                  # Current user, workspace, project, last sync
```

### Workspaces
```bash
agentsecrets workspace create "Name"       # Create workspace
agentsecrets workspace list                # List workspaces
agentsecrets workspace switch "Name"       # Switch active workspace
agentsecrets workspace invite user@email   # Invite teammate
```

### Projects
```bash
agentsecrets project create my-app        # Create project
agentsecrets project list                 # List projects in current workspace
agentsecrets project use my-app           # Set active project
agentsecrets project update my-app        # Update project
agentsecrets project delete my-app        # Delete project
```

### Secrets
```bash
agentsecrets secrets set KEY=value        # Store a secret
agentsecrets secrets get KEY              # Retrieve a value (you see it, agent doesn't)
agentsecrets secrets list                 # List key names — never values
agentsecrets secrets push                 # Upload .env to cloud (encrypted)
agentsecrets secrets pull                 # Download cloud secrets to keychain
agentsecrets secrets delete KEY           # Remove a secret
agentsecrets secrets diff                 # Compare local vs cloud
```

### Proxy
```bash
agentsecrets call --url <URL> --bearer KEY    # One-shot authenticated call
agentsecrets proxy start [--port 8765]        # Start HTTP proxy
agentsecrets proxy status                     # Check proxy status
agentsecrets proxy logs [--last N]            # View audit log
agentsecrets exec                             # OpenClaw exec provider (reads stdin)
agentsecrets mcp serve                        # Start MCP server
agentsecrets mcp install                      # Auto-configure AI tools
```

---

## vs. Traditional Secrets Management

| | AgentSecrets | HashiCorp Vault | AWS Secrets Manager | Doppler | 1Password |
|---|---|---|---|---|---|
| **Agent as operator** | ✅ Full lifecycle | ❌ Consumer only | ❌ Consumer only | ❌ Consumer only | ❌ Consumer only |
| **Zero-knowledge end to end** | ✅ Every step | ❌ Agent retrieves value | ❌ Agent retrieves value | ❌ Agent retrieves value | ⚠️ Partial |
| **Prompt injection protection** | ✅ Structural | ❌ | ❌ | ❌ | ❌ |
| **AI-native workflow** | ✅ Built for it | ❌ | ❌ | ❌ | ❌ |
| **Team workspaces** | ✅ Built-in | ⚠️ Complex | ⚠️ IAM roles | ✅ | ✅ Vaults |
| **OS keychain storage** | ✅ | ❌ | ❌ | ❌ | ✅ |
| **Setup time** | ⚡ 1 minute | ⏱️ Hours | ⏱️ 30+ min | ⏱️ 10 min | ⏱️ 5 min |
| **Free** | ✅ | ✅ OSS | ⚠️ AWS costs | ⚠️ Limited | ❌ |
| **Secret rotation** | ❌ Coming soon | ✅ | ✅ | ✅ | ✅ |

---

## Use Cases

### Solo Developer
```bash
agentsecrets init
agentsecrets secrets set STRIPE_KEY=sk_live_...
agentsecrets mcp install
# Ask Claude to check your Stripe balance. It manages the call. Never sees the key.
```

### Team Onboarding
```bash
agentsecrets login
agentsecrets workspace switch "Acme Engineering"
agentsecrets project use payments-service
agentsecrets secrets pull
# Ready. No credential sharing. No .env files sent over Slack.
```

### Autonomous Agent Deployment
```bash
# Agent handles this entire flow without human intervention
agentsecrets secrets diff          # checks for drift
agentsecrets secrets pull          # syncs if needed
agentsecrets workspace switch production
agentsecrets secrets pull
npm run deploy
agentsecrets proxy logs            # audits what happened
```

### Incident Response at 2am
```bash
agentsecrets proxy start
# Claude queries logs, checks database state, calls APIs
# Full access. Zero credential exposure. Full audit trail.
# You debug. The agent never held your credentials.
```

---

## Architecture

Built with Go for universal compatibility:

- **Crypto**: X25519 key exchange + AES-256-GCM encryption + Argon2id key derivation
- **Keyring**: OS keychain integration (macOS Keychain, Linux Secret Service, Windows Credential Manager)
- **Proxy**: Local HTTP server with session token, SSRF protection, redirect stripping
- **Cloud**: Zero-knowledge backend — stores ciphertext only, structurally cannot decrypt
- **Distribution**: Single binary, ~5-10MB, no runtime dependencies

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) and [PROXY.md](docs/PROXY.md) for deep dives.

---

## Roadmap

- [x] Core CLI
- [x] Workspaces + Projects + Team invites
- [x] Zero-knowledge cloud sync
- [x] Credential proxy — 6 auth styles
- [x] MCP server (Claude Desktop, Cursor)
- [x] HTTP proxy server
- [x] OpenClaw skill + exec provider
- [x] Audit logging
- [x] Multi-platform binaries (macOS, Linux, Windows)
- [x] npm, pip, Homebrew distribution
- [x] secrets diff
- [x] Automatic JWT refresh
- [ ] Keychain-only global storage mode
- [ ] Secret rotation
- [ ] Environment support (dev/staging/prod)
- [ ] Web dashboard
- [ ] LangChain + CrewAI first-party integrations

---

## Security

Reporting vulnerabilities: do NOT open public issues.
Email: hello@theseventeen.co — response within 24 hours.

---

## Contributing

Found a bug? [Open an issue](https://github.com/The-17/agentsecrets/issues)
Have an idea? [Start a discussion](https://github.com/The-17/agentsecrets/discussions)
Want to contribute? Check [CONTRIBUTING.md](docs/CONTRIBUTING.md)

```bash
git clone https://github.com/The-17/agentsecrets
cd agentsecrets
go mod download
make build
make test
```

---

## Links

- **GitHub**: [github.com/The-17/agentsecrets](https://github.com/The-17/agentsecrets)
- **ClawHub**: [clawhub.ai/SteppaCodes/agentsecrets](https://clawhub.ai/SteppaCodes/agentsecrets)
- **Related**: [SecretsCLI](https://github.com/The-17/SecretsCLI) — original Python implementation

---

## License

MIT — see [LICENSE](LICENSE)

Built by [The Seventeen](https://github.com/The-17)

---

**The agent operates it. The agent never sees it.** ⭐
