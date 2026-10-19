# AgentSecrets

> **Zero-knowledge secrets infrastructure built for AI agents to operate, not just consume.**

Every other secrets tool was built for humans to provision credentials to agents. AgentSecrets was built for agents to manage credentials themselves — without ever seeing a single value.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)
[![ClawHub](https://img.shields.io/badge/ClawHub-agentsecrets-blue)](https://clawhub.ai/SteppaCodes/agentsecrets)

**[Official Website](https://agentsecrets.tech)** | **[Engineering Blog Series](https://engineering.theseventeen.co/series/building-agentsecrets)**

---

## What This Is

Most secrets tools treat AI agents as consumers, something that receives a credential and uses it. AgentSecrets treats the agent as an operator.

Your agent checks its own status, notices a secret is out of sync, pulls the latest from the cloud, makes the authenticated API call, and audits what it did. All of this without ever knowing a single credential value.

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

## Installation

**Homebrew (macOS / Linux):**
```bash
brew install The-17/tap/agentsecrets
```

**npm / npx:**
```bash
npm install -g @the-17/agentsecrets
# or without installing
npx @the-17/agentsecrets init
```

**pip:**
```bash
pip install agentsecrets-cli
```

**Go:**
```bash
go install github.com/The-17/agentsecrets/cmd/agentsecrets@v3.0.0
```

---

## Quick Start

```bash
# Set up your account (first time) or initialise a new project (returning user)
agentsecrets init

# Create a project
agentsecrets project create my-app

# Store credentials — values go to OS keychain, never to disk
agentsecrets secrets set STRIPE_KEY=sk_live_51H...
agentsecrets secrets set OPENAI_KEY=sk-proj-...
agentsecrets secrets set DATABASE_URL=postgresql://...

# Or push your existing .env all at once
agentsecrets secrets push

# Authorize the domains your agents can reach
agentsecrets workspace allowlist add api.stripe.com api.openai.com

# Connect your AI tool
npx @the-17/agentsecrets mcp install   # Claude Desktop + Cursor
agentsecrets proxy start               # Any agent via HTTP
openclaw skill install agentsecrets    # OpenClaw

# Or inject secrets as env vars into any process
agentsecrets env -- stripe mcp
agentsecrets env -- node server.js
agentsecrets env -- npm run dev
```

Your agent now has full API access. It will never see a credential value.

---

## Full Command Reference

See the [Official Documentation](https://agentsecrets.tech) for the full command reference and architecture deep dives.

---

## License

MIT — see [LICENSE](https://github.com/The-17/agentsecrets/blob/main/LICENSE)

Built by [The Seventeen](https://theseventeen.co)

**The agent operates it. The agent never sees it.** ⭐
