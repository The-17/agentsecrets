# Quick Start

Get AgentSecrets running in under 5 minutes.

---

## Install

**macOS (Homebrew):**
```bash
brew install the-17/tap/agentsecrets
```

**npm (Node.js projects):**
```bash
npm install -g @the-17/agentsecrets
```

**PyPI (Python projects):**
```bash
pip install agentsecrets
```

**From source (Go 1.21+):**
```bash
git clone https://github.com/The-17/agentsecrets
cd agentsecrets
go build -o agentsecrets ./cmd/agentsecrets
```

Verify:
```bash
agentsecrets --version
```

---

## 1. Create Your Account

```bash
agentsecrets init
```

This will:
1. Ask: **Create a new account** or **Log in** to an existing one
2. Ask which **storage mode** to use:
   - **Keychain (recommended)** — secrets go to the OS keychain, no `.env` file is created
   - **Standard** — secrets are written to a `.env` file (traditional workflow)
3. Generate a cryptographic keypair on your machine — your private key never leaves your device
4. Write `.agent/workflows/agentsecrets.md` — the workflow file that teaches any AI assistant how to use AgentSecrets automatically

**Skip the interactive prompts:**
```bash
agentsecrets init --storage-mode 1   # Keychain mode (default)
agentsecrets init --storage-mode 2   # Standard .env mode
```

---

## 2. Create a Project

Projects map to your applications. Secrets are partitioned by project.

```bash
agentsecrets project create my-app
```

This writes `.agentsecrets/project.json` in the current directory, linking it to the remote project. Every `secrets` operation uses this project context.

---

## 3. Store Secrets

Values are encrypted client-side before leaving your machine:

```bash
agentsecrets secrets set STRIPE_KEY=sk_live_51H...
agentsecrets secrets set DATABASE_URL=postgresql://user:pass@host/db
agentsecrets secrets set OPENAI_KEY=sk-proj-...
```

Or import an existing `.env` file all at once:

```bash
agentsecrets secrets push
```

Verify what's stored (key names only — values are never shown):

```bash
agentsecrets secrets list
```

---

## 4. Authorize Your Domains

Before making any proxy calls, tell AgentSecrets which API domains your project is allowed to reach. This is the zero-trust allowlist, calls to unauthorized domains are blocked.

```bash
agentsecrets workspace allowlist add api.stripe.com api.openai.com
```

This requires your password and takes effect immediately.

---

## 5. Connect Your AI Tool

### Claude Desktop / Cursor / Windsurf (MCP)

```bash
agentsecrets mcp install
```

This auto-configures MCP for Claude Desktop and Cursor. Restart your AI tool. You'll see two new tools: `api_call` and `list_secrets`.

### HTTP Proxy (any agent or framework)

```bash
agentsecrets proxy start
```

Then route requests through `http://localhost:8765/proxy` with `X-AS-*` injection headers.

### OpenClaw

```bash
openclaw skill install agentsecrets
```

### Any CLI Tool (env var injection)

```bash
agentsecrets env -- stripe mcp
agentsecrets env -- node server.js
agentsecrets env -- python manage.py runserver
```

---

## 6. Make Your First Authenticated API Call

```bash
# One-shot authenticated call — agent uses key name, proxy resolves from keychain
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY
```

Output:
```
HTTP 200

{"object":"balance","available":[{"amount":10000,"currency":"usd",...}]}
```

What was sent to Stripe: `Authorization: Bearer sk_live_51H...`  
What you (or your agent) saw: the API response only.

---

## 7. Check Your Audit Log

```bash
agentsecrets proxy logs --last 5
```

```
TIME      RESULT  METHOD  URL                              KEY          AUTH    STATUS  REASON  DURATION
14:23:01  ✓ OK    GET     api.stripe.com/v1/balance        STRIPE_KEY   bearer  200     -       245ms
```

---

## Next Steps

- [Command Reference](commands/) — full reference for every subcommand
- [Proxy & MCP](PROXY.md) — deep dive into proxy authentication styles
- [Architecture](ARCHITECTURE.md) — how the encryption model works
- [Contributing](CONTRIBUTING.md) — how to contribute