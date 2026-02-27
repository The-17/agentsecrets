# AgentSecrets

> **The credential firewall for the AI era.**

Traditional vaults protect keys at rest. AgentSecrets protects keys in motion, from an agent that should never have held them at all.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)
[![ClawHub](https://img.shields.io/badge/ClawHub-agentsecrets-blue)](https://clawhub.ai/SteppaCodes/agentsecrets)

---

## The Problem

AI agents doing real work (deployments, API calls, database queries) need credentials to function. Every current approach gives the agent the actual values. That's the mistake.

```
# What everyone is doing today
STRIPE_KEY=sk_live_51H...  ← plaintext .env file
                              ← any plugin reads this
                              ← any prompt injection reaches this
                              ← any CVE exposes this
```

Check Point Research published CVE-2026-21852: API key exfiltration through malicious project configs in AI coding tools. TrendMicro documented 335 malicious OpenClaw skills harvesting credentials from plaintext files. Cisco demonstrated a skill that silently exfiltrated keys using curl. Bitsight asked an AI agent to find API keys on the filesystem. It did.

Every one of these attacks worked because the agent held credential values. Anything that can influence the agent can reach them.

**AgentSecrets fixes this at the architecture level. The agent never holds credential values. Not in memory. Not in config files. Not in environment variables. Never.**


## How It Works

```
Your Agent                    AgentSecrets                 Any API
    |                              |                           |
    | "use STRIPE_KEY" ----------->|                           |
    |                              |-- OS keychain lookup      |
    |                              |<-- sk_live_51H...         |
    |                              |                           |
    |                              |-- inject bearer header -> |
    |                              |-- forward request ------> |
    |                              |<-- API response ----------|
    |                              |                           |
    |<-- {"balance": ...} ---------|                           |
    |                              |                           |
    | Never saw: sk_live_51H...    |                           |
```

The agent knows `STRIPE_KEY` exists. It knows Stripe returned a balance. It never knows that `STRIPE_KEY` is `sk_live_51H...`.

A prompt injection attack redirecting your agent to exfiltrate credentials gets: a key name. A malicious plugin searching your filesystem finds: nothing. A CVE reading your config files finds: nothing. **You cannot steal what was never there.**


## Installation

**npm / npx:**
```bash
npm install -g @the-17/agentsecrets
# or run without installing
npx @the-17/agentsecrets init
```

**Homebrew:**
```bash
brew install The-17/tap/agentsecrets
```

**Python:**
```bash
pip install agentsecrets
```

**Go (source):**
```bash
go install github.com/The-17/agentsecrets/cmd/agentsecrets@latest
```


## Quick Start

```bash
# Create account + encryption keys
agentsecrets init

# Create a project
agentsecrets project create my-app

# Store credentials in OS keychain (never written to disk as plaintext)
agentsecrets secrets set STRIPE_KEY=sk_live_51H...
agentsecrets secrets set OPENAI_KEY=sk-proj-...
agentsecrets secrets set DATABASE_URL=postgresql://...

# Or push your existing .env
agentsecrets secrets push

# Connect your AI tool
npx @the-17/agentsecrets mcp install   # Claude Desktop + Cursor
# or
agentsecrets proxy start               # Any agent via HTTP proxy
# or
cp -r integrations/openclaw ~/.openclaw/skills/agentsecrets  # OpenClaw
```

From this point your agent has full API access. It never sees a credential value.


## The Credential Proxy

AgentSecrets runs a local HTTP proxy on `localhost:8765`. Agents send requests with injection headers. The proxy resolves the real credential from your OS keychain, injects it, forwards the request, and returns only the response.

```bash
# One-shot authenticated call
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY

# Start persistent proxy
agentsecrets proxy start

# Agent sends requests like this
curl http://localhost:8765/proxy \
  -H "X-AS-Target-URL: https://api.stripe.com/v1/balance" \
  -H "X-AS-Inject-Bearer: STRIPE_KEY"
```

### 6 Auth Styles — Every API Covered

```bash
# Bearer token (Stripe, OpenAI, GitHub, most modern APIs)
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY

# Custom header (SendGrid, AWS API Gateway, Twilio)
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

# Multiple credentials in one call
agentsecrets call --url https://api.example.com/data \
  --bearer AUTH_TOKEN \
  --header X-Org-ID=ORG_SECRET
```

---

## Team Workspaces

AgentSecrets is built for teams. A workspace is a shared environment — your team gets added and gets access to the projects within it. Credentials are encrypted client-side before upload. The server stores only encrypted blobs it cannot read.

```bash
# Create a workspace for your team
agentsecrets workspace create "Acme Engineering"

# Invite teammates
agentsecrets workspace invite alice@acme.com
agentsecrets workspace invite bob@acme.com

# Everyone on the team works in the same workspace
agentsecrets workspace switch "Acme Engineering"

# Projects partition secrets by service or environment
agentsecrets project create payments-service
agentsecrets project create auth-service
agentsecrets project create data-pipeline
```

**What this means for your team:**
- New developer joins → `agentsecrets login` → `agentsecrets workspace switch "Acme Engineering"` → `agentsecrets secrets pull` → ready to work. No Slack messages asking for credentials. No `.env` files emailed around.
- Secrets are shared through the encrypted cloud layer. Nobody shares values directly. Nobody has to trust anyone not to leak them.
- The AI agents every teammate runs have access to the credentials they need. None of them ever see the values.

---

## Audit Trail

Every authenticated call is logged locally. Key names only — the log struct has no value field, making it structurally impossible to accidentally log a credential value.

```bash
agentsecrets proxy logs
agentsecrets proxy logs --secret STRIPE_KEY
agentsecrets proxy logs --last 50
```

```
Time      Method  Target URL                              Secret      Status  Duration
01:15:00  GET     https://api.stripe.com/v1/balance       STRIPE_KEY  200     245ms
01:16:30  POST    https://api.openai.com/v1/chat/...      OPENAI_KEY  200     1203ms
01:31:00  GET     https://api.github.com/repos/...        GITHUB_KEY  200     189ms
```

Raw JSONL at `~/.agentsecrets/proxy.log` — pipe to jq, ship to your logging infrastructure, query however you need.

```bash
# Find unexpected API calls
cat ~/.agentsecrets/proxy.log | jq 'select(.target_url | contains("stripe") | not)'

# Count calls by credential
cat ~/.agentsecrets/proxy.log | jq -r '.secret_key' | sort | uniq -c

# Find failures
cat ~/.agentsecrets/proxy.log | jq 'select(.status_code >= 400)'
```

---

## Security Model

| Layer | Implementation |
|---|---|
| Key exchange | X25519 (NaCl SealedBox) |
| Secret encryption | AES-256-GCM |
| Key derivation | Argon2id |
| Key storage | OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) |
| Transport | HTTPS / TLS |
| Server | Zero-knowledge — stores encrypted blobs only |
| Proxy | Session token, SSRF protection, redirect stripping |

**What AgentSecrets protects against:**
- Prompt injection credential exfiltration — agent never holds values to leak
- Malicious plugin/skill credential theft — nothing in filesystem to steal
- Config file CVEs (CVE-2026-21852, CVE-2025-59536) — no values in config files
- Plaintext credential exposure — OS keychain only, never written to disk

**Honest limitations:**
- Does not sandbox agent network access — a malicious plugin with independent network access can still make its own calls
- Does not replace production secrets management (Vault, AWS Secrets Manager) for server-side workloads
- Secret rotation not yet implemented (coming)


## AI Tool Integrations

### Claude Desktop + Cursor (MCP)

```bash
npx @the-17/agentsecrets mcp install
```

Auto-configures your MCP setup. Claude gets an `api_call` tool. Ask Claude to call any API — AgentSecrets handles the credential. Claude sees only the response.

Manual config for `claude_desktop_config.json`:
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

No API keys in the config file. Nothing to steal.

### OpenClaw

```bash
# ClawHub
openclaw skill install agentsecrets

# Manual
cp -r integrations/openclaw ~/.openclaw/skills/agentsecrets
```

Your OpenClaw agent calls APIs through AgentSecrets. The ClawHavoc malware searching for credentials finds nothing in `auth-profiles.json`.

### Any AI Assistant (Workflow File)

`agentsecrets init` creates `.agent/workflows/api-call.md` — a workflow file that teaches any AI assistant (Claude, Gemini, Copilot, etc.) how to use AgentSecrets automatically. Works with any tool that supports workflow or instruction files.

### HTTP Proxy (Any Agent or Framework)

```bash
agentsecrets proxy start

# Any agent that can make HTTP requests
curl http://localhost:8765/proxy \
  -H "X-AS-Target-URL: https://api.stripe.com/v1/charges" \
  -H "X-AS-Inject-Bearer: STRIPE_KEY"
```

Works with LangChain, CrewAI, AutoGen, custom agents — anything that makes HTTP requests.

---

## Secrets Management

```bash
agentsecrets secrets set KEY=value       # Store a secret
agentsecrets secrets get KEY             # Retrieve a secret (you see it, agent doesn't)
agentsecrets secrets list                # List key names (never values)
agentsecrets secrets push                # Upload local .env to cloud (encrypted)
agentsecrets secrets pull                # Download cloud secrets to .env
agentsecrets secrets delete KEY          # Remove a secret
agentsecrets secrets diff                # Compare local vs cloud — see what's out of sync
```

---

## Full Command Reference

### Account
```bash
agentsecrets init          # Create account or login
agentsecrets login         # Login to existing account
agentsecrets logout        # Clear session
agentsecrets status        # Current user, workspace, project, last sync
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
agentsecrets project list                  # List projects in current workspace
agentsecrets project use my-app           # Set active project
```

### Proxy
```bash
agentsecrets call --url <URL> --bearer KEY   # One-shot authenticated call
agentsecrets proxy start [--port 8765]       # Start HTTP proxy
agentsecrets proxy status                    # Check proxy status
agentsecrets proxy logs [--last N]           # View audit log
agentsecrets mcp serve                       # Start MCP server
agentsecrets mcp install                     # Auto-configure AI tools
```

---

## vs. Traditional Secrets Management

| | AgentSecrets | HashiCorp Vault | AWS Secrets Manager | Doppler | 1Password |
|---|---|---|---|---|---|
| **AI-Native** | ✅ Built for it | ❌ | ❌ | ❌ | ❌ |
| **Agent never sees values** | ✅ Proxy injects | ❌ Agent retrieves | ❌ Agent retrieves | ❌ Agent retrieves | ❌ Agent retrieves |
| **Prompt injection protection** | ✅ Structural | ❌ | ❌ | ❌ | ❌ |
| **Zero-knowledge server** | ✅ | ❌ | ❌ | ❌ | ✅ |
| **Team workspaces** | ✅ Built-in | ⚠️ Complex | ⚠️ IAM roles | ✅ | ✅ Vaults |
| **Setup time** | ⚡ 1 minute | ⏱️ Hours | ⏱️ 30+ min | ⏱️ 10 min | ⏱️ 5 min |
| **OS keychain storage** | ✅ | ❌ | ❌ | ❌ | ✅ |
| **Free** | ✅ | ✅ OSS | ⚠️ AWS costs | ⚠️ Limited | ❌ |

**The key difference:** Every traditional vault protects secrets at rest. Once an agent retrieves a key to use it, that key is in the agent's memory — vulnerable to prompt injection, malicious plugins, and CVEs. AgentSecrets never gives the agent the key. The injection happens at the transport layer, outside the agent's observable context. That's a fundamentally different security model.

---

## Use Cases

### Solo Developer
```bash
agentsecrets init
agentsecrets secrets set STRIPE_KEY=sk_live_...
agentsecrets mcp install
# Ask Claude to check your Stripe balance. It never sees the key.
```

### Team Onboarding
```bash
# New developer joins the team
agentsecrets login
agentsecrets workspace switch "Acme Engineering"
agentsecrets project use payments-service
agentsecrets secrets pull
# Ready. No credential sharing. No .env files emailed around.
```

### Multi-Environment Deployment
```bash
agentsecrets workspace switch staging
agentsecrets project use my-app
agentsecrets secrets pull
npm run deploy

agentsecrets workspace switch production
agentsecrets secrets pull
npm run deploy
# AI agent handled both. Saw neither set of credentials.
```

### Microservices
```bash
agentsecrets project use auth-service && agentsecrets secrets pull
agentsecrets project use api-gateway && agentsecrets secrets pull
agentsecrets project use payment-service && agentsecrets secrets pull
```

### Incident Response
```bash
# 2am. Something broke. You're debugging with Claude.
agentsecrets proxy start
# Claude queries logs, checks database state, calls APIs.
# Full access. Zero credential exposure. Full audit trail.
```

---

## Architecture

Built with Go for universal compatibility:

- **Crypto**: X25519 key exchange + AES-256-GCM encryption + Argon2id key derivation
- **Keyring**: OS keychain integration (macOS Keychain, Linux Secret Service, Windows Credential Manager)
- **Proxy**: Local HTTP server with session token, SSRF protection, redirect stripping
- **Cloud**: Zero-knowledge backend — stores encrypted blobs only, cannot decrypt
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
- [x] OpenClaw native skill
- [x] Audit logging
- [x] Multi-platform binaries (macOS, Linux, Windows)
- [x] npm, pip, Homebrew distribution
- [x] Keychain-only mode (global storage preference)
- [x] 1.0 release
- [ ] Secret rotation
- [ ] Environment support (dev/staging/prod)
- [ ] Web dashboard
- [ ] LangChain + CrewAI first-party integrations
- [ ] 1Password / Vault migration guides


---

## Security

**Reporting vulnerabilities:** Do NOT open public issues.
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
- **Website**: agentsecrets.com (coming soon)
- **Docs**: docs.agentsecrets.com (coming soon)
- **Related**: [SecretsCLI](https://github.com/The-17/SecretsCLI) — original Python implementation

---

## License

MIT — see [LICENSE](LICENSE)

Built by [The Seventeen](https://theseventeen.co)

---

**Your agent makes the call. It never sees the key.** ⭐
