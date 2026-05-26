# AgentSecrets

> Zero-knowledge AI Agent Secrets Management: secure API keys for AI agents without exposing credential values at runtime. Store, sync, inject, audit, and build on top of credentials your agents can use but never see.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)
[![Stars](https://img.shields.io/github/stars/The-17/agentsecrets?style=flat)](https://github.com/The-17/agentsecrets/stargazers)
[![ClawHub](https://img.shields.io/badge/ClawHub-agentsecrets-blue)](https:/a/clawhub.ai/SteppaCodes/agentsecrets)

**[Website](https://agentsecrets.theseventeen.co)** | **[Docs](https://agentsecrets.theseventeen.co/docs)** | **[Engineering Blog](https://engineering.theseventeen.co/series/building-agentsecrets)**

---

AgentSecrets is the complete secrets management and credential infrastructure for the AI agent era. It covers secrets storage, zero-knowledge cloud sync, environment management, team workspaces, agent identity, audit logging, transport-layer credential injection, and an SDK for building on top, all without a credential value ever entering agent context., the agent sees only the API response. At no step does the agent hold, see, or have access to the actual credential value. The zero-knowledge guarantee is architectural, not policy-based. It is built into how the system works at every layer.

---

## Contents

- [Why the Architecture Matters](#why-the-architecture-matters)
- [What AgentSecrets Is](#what-agentsecrets-is)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [The Agent Workflow](#the-agent-workflow)
- [Environments](#environments)
- [Team Workspaces](#team-workspaces)
- [Agent Identity](#agent-identity)
- [6 Auth Injection Styles](#6-auth-injection-styles)
- [Zero-Trust Proxy Security](#zero-trust-proxy-security)
- [Encryption Model](#encryption-model)
- [AI Tool Integrations](#ai-tool-integrations)
- [Build on AgentSecrets](#build-on-agentsecrets)
- [Full Command Reference](#full-command-reference)
- [Roadmap](#roadmap)
- [Security](#security)
- [Contributing](#contributing)

---

> **Package rename notice**
> The `agentsecrets` PyPI package is now the [AgentSecrets SDK](https://github.com/The-17/agentsecrets-sdk): for developers building tools and agents on AgentSecrets infrastructure. The CLI wrapper is now `agentsecrets-cli`. The `agentsecrets` command itself is unchanged.

---

## The Critical Difference

There are two fundamentally different approaches to secrets management for AI agents.

**Runtime retrieval (the common pattern)**

The agent fetches or leases a credential at runtime. The value enters agent memory.

```bash
export TOKEN=$(secrets lease github_token)
# The agent now holds sk_live_51H... in memory
```

Once the value enters agent context, it can be extracted via prompt injection, exposed in logs or traces, and accessed by tools, plugins, or any dependency running in the same process.

**Zero-knowledge injection (AgentSecrets)**

The agent references a key name. The value is resolved outside the agent and injected at the transport layer.

```bash
agentsecrets call --bearer GITHUB_TOKEN
# The agent referenced a name. It never received a value.
```

If a system gives an AI agent access to a credential value, it must accept that the value can be leaked. AgentSecrets removes that assumption entirely.

---

## Why the Architecture Matters

Most approaches to AI agent credential security follow the same pattern: store secrets securely, then retrieve and inject them at runtime.

```
Secure store → agent retrieves sk_live_51H... → value enters agent memory
                                               → prompt injection can reach it
                                               → malicious plugin can read it
                                               → CVE exposes it
                                               → LLM trace captures it
```

Whether the store is a .env file, HashiCorp Vault, AWS Secrets Manager, or a leasing system, if the agent retrieves the value, the value is in agent context. That is the moment of exposure.

AgentSecrets eliminates that moment entirely.

```
OS keychain → proxy resolves in memory → value injected at transport layer
                                       → agent receives API response only
                                       → value never entered agent context
                                       → nothing to steal, log, or extract
```

The agent never retrieves the value. It cannot be prompted to reveal it. It cannot be logged. It cannot be stolen through a plugin or CVE. It was structurally absent from every place an attack would look.

---

## What AgentSecrets Is

**Credential proxy:** six auth injection styles, domain allowlist enforcement, response body redaction, SSRF protection, session token authentication.

**Zero-knowledge cloud sync:** X25519 key exchange, AES-256-GCM encryption, Argon2id key derivation. The server stores ciphertext it structurally cannot decrypt. The workspace key lives in the OS keychain and never reaches the server.

**Environment support:** development, staging, and production as first-class concepts. One command switches the active environment. The proxy resolves the right credentials automatically. Cross-environment diff shows coverage gaps.

**Team workspaces:** secrets encrypted client-side before upload. New developers onboard by pulling from the workspace. No .env files shared over Slack, no credential spreadsheets, no production keys in Slack DMs.

**Agent identity:** three levels: anonymous, declared, and cryptographically issued. Every proxy call is logged against the agent that made it. Tokens can be revoked per agent without touching anything else.

**Governance audit log:** every call logged with key name, endpoint, environment, agent identity, status, and the domain allowlist state at the exact moment of execution. No value field exists in the schema.

**SDK:** build tools, MCP servers, and AI agents where credential values never enter your code or the code of anyone using what you build.

**MCP integration:** first-class MCP server for Claude Desktop and Cursor. No credential values in any config file.

**Environment variable injection:** `agentsecrets env -- <command>` wraps any process and injects secrets from the OS keychain at spawn time. Nothing written to disk.

---

## Installation

```bash
# Homebrew (macOS / Linux)
brew install The-17/tap/agentsecrets

# npm
npm install -g @the-17/agentsecrets

# pip
pip install agentsecrets-cli

# Go (recommend using a pinned version for supply chain security)
go install github.com/The-17/agentsecrets/cmd/agentsecrets@v2.0.0
```

---

## Quick Start

```bash
agentsecrets init

agentsecrets project create my-agent

agentsecrets secrets set STRIPE_KEY=sk_live_51H...
agentsecrets secrets set OPENAI_KEY=sk-proj-...

agentsecrets workspace allowlist add api.stripe.com api.openai.com

agentsecrets mcp install        # Claude Desktop + Cursor
agentsecrets proxy start        # any agent via HTTP proxy
```

---

## The Agent Workflow

This is what AgentSecrets looks like when an AI agent operates the full credentials lifecycle autonomously.

```bash
agentsecrets status
# Workspace:    Acme Engineering
# Project:      payments-service
# Environment:  production
# Last pull:    2 minutes ago

agentsecrets secrets diff
# OUT OF SYNC: STRIPE_KEY (remote is newer)

agentsecrets secrets pull
# Synced 1 secret from cloud to OS keychain

agentsecrets call \
  --url https://api.stripe.com/v1/balance \
  --bearer STRIPE_KEY
# {"object":"balance","available":[{"amount":420000,"currency":"usd"}]}

agentsecrets proxy logs --last 5
# 14:23:01  GET  api.stripe.com/v1/balance  STRIPE_KEY  200  245ms
```

The agent managed the complete workflow. No credential value appeared at any step. The audit log has no value field because there was no value to log.

---

## Environments

Every project has three built-in environments. One command switches the active context. The proxy, push, pull, and diff commands all respect the active environment automatically.

```bash
agentsecrets environment switch production

agentsecrets environment list
#   development   12 secrets
#   staging        8 secrets
#   production    12 secrets   ← active

agentsecrets secrets diff --from development --to production
# In development but missing in production:
#   OPENAI_KEY
#   DATABASE_URL

agentsecrets environment merge staging production
# Prompts for production values for each staging key
```

---

## Team Workspaces

```bash
agentsecrets workspace create "The Seventeen Engineering"
agentsecrets workspace invite alice@theseventeen.co bob@theseventeen.co

agentsecrets project create payments-service
agentsecrets project create auth-service
```

New developer onboards:
```bash
agentsecrets login
agentsecrets workspace switch "The Seventeen Engineering"
agentsecrets project use payments-service
agentsecrets secrets pull
# Ready. No credential sharing. No .env files sent over Slack.
```

---

## Agent Identity

```bash
# Declared identity
client = AgentSecrets(agent_id="billing-processor")

# Issued identity, cryptographically verified on every call
agentsecrets agent token issue "billing-processor"
# → agt_ws01hxyz_4kR9mNpQ...
client = AgentSecrets(agent_token="agt_ws01hxyz_...")

# Audit by agent
agentsecrets log list --agent billing-processor
agentsecrets log list --identity anonymous   # find coverage gaps
```

---

## 6 Auth Injection Styles

```bash
# Bearer token
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY

# Custom header
agentsecrets call --url https://api.sendgrid.com/v3/mail/send \
  --header X-Api-Key=SENDGRID_KEY

# Query parameter
agentsecrets call \
  --url "https://maps.googleapis.com/maps/api/geocode/json?address=Lagos" \
  --query key=GOOGLE_MAPS_KEY

# Basic auth
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

## Zero-Trust Proxy Security

Every proxied request passes through four security layers before injection:

**Domain allowlist:** deny-by-default. Every target domain must be explicitly authorized. Unauthorized domains are blocked before credential resolution, regardless of whether the request came from prompt injection, SSRF, or misconfiguration.

**Response body redaction:** if an external API echoes the injected credential in its response, the proxy replaces it with `[REDACTED_BY_AGENTSECRETS]` before the response reaches the agent.

**SSRF protection:** private IP ranges, localhost, and non-HTTPS targets are blocked at the proxy level.

**Session token:** generated at proxy startup, required on every request. Blocks rogue processes on the same machine from using the proxy.

```bash
agentsecrets workspace allowlist add api.stripe.com api.openai.com
agentsecrets workspace allowlist list
agentsecrets workspace allowlist log   # view blocked attempts
```

---

## Encryption Model

| Layer | Implementation |
|---|---|
| Key exchange | X25519 (NaCl SealedBox) |
| Secret encryption | AES-256-GCM |
| Key derivation | Argon2id |
| Key storage | OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) |
| Transport | HTTPS / TLS |
| Server | Stores ciphertext only, structurally cannot decrypt |

---

## AI Tool Integrations

### Claude Desktop + Cursor

```bash
agentsecrets mcp install
```

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

### OpenClaw

```bash
openclaw skill install agentsecrets
```

Native exec provider for OpenClaw's SecretRef system. Credentials resolve at execution time through the AgentSecrets binary. Nothing in any OpenClaw config file.

### Environment Variable Injection

```bash
agentsecrets env -- stripe mcp
agentsecrets env -- node server.js
agentsecrets env -- python manage.py runserver
agentsecrets env -- npm run dev
```

Values injected into child process memory at spawn time. Nothing written to disk. Gone when the process exits.

### HTTP Proxy

```bash
agentsecrets proxy start

curl http://localhost:8765/proxy \
  -H "X-AS-Target-URL: https://api.stripe.com/v1/balance" \
  -H "X-AS-Inject-Bearer: STRIPE_KEY"
```

Works with LangChain, CrewAI, AutoGen, and any framework that makes HTTP requests.

---

## Build on AgentSecrets

```python
pip install agentsecrets
```

```python
from agentsecrets import AgentSecrets

client = AgentSecrets()
response = client.call(
    url="https://api.stripe.com/v1/balance",
    bearer="STRIPE_KEY"
)
```

The SDK has no `get()` method. There is no way to retrieve a credential value into calling code. The only operations available are the ones that keep the value out of agent context. The secure path is the only path.

**Built on the SDK:**
- [Zero-Knowledge MCP Template](https://github.com/The-17/zero-knowledge-mcp): scaffold for MCP servers with zero credential storage
- [AgentSecrets for LangChain](https://github.com/The-17/agentsecrets-langchain): zero-knowledge API calls in any LangChain agent *(coming soon)*
- [AgentSecrets JS SDK](https://github.com/The-17/agentsecrets-js-sdk) *(coming soon)*

---

## Full Command Reference

### Account
```bash
agentsecrets init                    # Set up account or initialise a new project
agentsecrets login                   # Login to existing account
agentsecrets logout                  # Clear session
agentsecrets status                  # Workspace, project, environment, last sync
```

### Workspaces
```bash
agentsecrets workspace create "Name"
agentsecrets workspace list
agentsecrets workspace switch "Name"
agentsecrets workspace invite user1@email.com user2@email.com
agentsecrets workspace promote user@email.com
agentsecrets workspace demote user@email.com
agentsecrets workspace allowlist add <domain>
agentsecrets workspace allowlist list
agentsecrets workspace allowlist log
```

### Projects
```bash
agentsecrets project create NAME
agentsecrets project list
agentsecrets project use NAME
agentsecrets project update NAME
agentsecrets project delete NAME
agentsecrets project invite user@email.com
```

### Environments
```bash
agentsecrets environment switch <n>
agentsecrets environment list
agentsecrets environment copy <from> <to>
agentsecrets environment merge <from> <to>
agentsecrets environment clean
```

### Secrets
```bash
agentsecrets secrets set KEY=value
agentsecrets secrets list
agentsecrets secrets push
agentsecrets secrets pull
agentsecrets secrets delete KEY
agentsecrets secrets diff
agentsecrets secrets diff --from X --to Y
```

### Proxy and Calls
```bash
agentsecrets call --url URL --bearer KEY
agentsecrets proxy start [--port 8765]
agentsecrets proxy status
agentsecrets proxy stop
agentsecrets proxy logs [--last N] [--watch] [--env ENV]
agentsecrets mcp serve
agentsecrets mcp install
agentsecrets exec
agentsecrets env -- <command>
```

### Audit
```bash
agentsecrets log list [--tail] [--agent NAME] [--identity anonymous]
agentsecrets log summary [--since 7d]
agentsecrets log export --format csv
agentsecrets log detail <id>
```

### Agent Identity
```bash
agentsecrets agent list
agentsecrets agent delete <n>
agentsecrets agent token issue <n>
agentsecrets agent token list <n>
agentsecrets agent token revoke <id> --agent="<n>"
```

---

## Roadmap

- [x] Core CLI
- [x] Zero-knowledge cloud sync
- [x] Credential proxy with 6 auth styles
- [x] Workspaces, projects, team invites
- [x] MCP server (Claude Desktop, Cursor)
- [x] HTTP proxy server
- [x] OpenClaw skill + exec provider
- [x] Governance audit log
- [x] Agent identity + token management
- [x] Environment support (development / staging / production)
- [x] Domain allowlist + response body redaction
- [x] `agentsecrets env` for environment variable injection
- [x] Python SDK
- [x] Zero-Knowledge MCP Template
- [x] Multi-platform binaries (macOS, Linux, Windows)
- [x] npm, pip, Homebrew distribution
- [ ] AgentSecrets for LangChain
- [ ] AgentSecrets for CrewAI
- [ ] JavaScript / Node.js SDK
- [ ] Secret rotation
- [ ] Web dashboard
- [ ] Cloud resolver (serverless + production deployments)
- [ ] AgentSecrets Connect (multi-tenant credential delegation)

---

## Security

### Trust Model & OS Keychain
AgentSecrets delegates authentication and cryptography to the user's local OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service). Be mindful of which workspace and environment you configure for your agents, as they will have access to any credentials provisioned in that specific scope. However, unwanted actions and API calls are heavily mitigated by the domain allowlist, which bounds where agents can send those credentials.

### Audit Logging Privacy
Every proxy call is recorded in a persistent audit log (locally at `~/.agentsecrets/proxy.log` and globally in the cloud). The log records endpoints, timestamps, and key names (e.g., `STRIPE_KEY`), but never the actual values. **Do not put sensitive data in the key names themselves.**

### Supply Chain Security
Your security depends on the integrity of the installed `agentsecrets` package. We strongly recommend installing from official sources (like Homebrew) which verify package hashes, or using pinned versions for `go install` (e.g., `@v2.0.0` instead of `@latest`) to mitigate upstream supply chain poisoning.

Vulnerabilities: do NOT open public issues.
Email: engineering@theseventeen.co, response within 24 hours.

---

## Contributing

```bash
git clone https://github.com/The-17/agentsecrets
cd agentsecrets
go mod download
make build
make test
```

Found a bug? [Open an issue](https://github.com/The-17/agentsecrets/issues)
Have an idea? [Start a discussion](https://github.com/The-17/agentsecrets/discussions)
Want to contribute? [CONTRIBUTING.md](docs/CONTRIBUTING.md)

---

## Links

- **Website**: [agentsecrets.theseventeen.co](https://agentsecrets.theseventeen.co)
- **Docs**: [agentsecrets.theseventeen.co/docs](https://agentsecrets.theseventeen.co/docs)
- **Engineering Blog**: [engineering.theseventeen.co/series/building-agentsecrets](engineering.theseventeen.co/series/building-agentsecrets)
- **SDK**: [github.com/The-17/agentsecrets-sdk](github.com/The-17/agentsecrets-sdk)
- **ClawHub**: [clawhub.ai/SteppaCodes/agentsecrets](clawhub.ai/SteppaCodes/agentsecrets)

- ---
## License
MIT. See [LICENSE](LICENSE)

Built by [The Seventeen](https://theseventeen.co)

---

*You cannot steal what was never there.*
