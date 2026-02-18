# AgentSecrets

> **The first secrets manager built for the AI era**

Stop pasting API keys into ChatGPT. AgentSecrets lets your AI assistant help with deployments without ever seeing your credentials.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)

---

## The Problem

You're coding with Claude, ChatGPT, or Copilot and need to deploy your app:

```
You: "Help me deploy to production"
AI: "Sure! I need your DATABASE_URL, API keys..."
You: *pastes secrets into chat* 😱
```

**This is insecure.** Your secrets are now in chat logs, training data, and who knows where else.

## The Solution

AgentSecrets lets AI assistants manage the *workflow* of secrets without ever seeing the actual values:

```bash
# AI runs this for you
agentsecrets workspace switch production
agentsecrets project use my-app
agentsecrets secrets pull

# Secrets loaded → AI helps deploy
# AI never sees the values 
```

**Zero-knowledge for AI**: Your assistant knows secrets *exist* (by key name), but never sees the actual values.

---

## Quick Start

### Installation

**macOS/Linux:**
```bash
curl -sSL https://get.agentsecrets.com | sh
```

**Python (includes binary):**
```bash
pip install agentsecrets
```

**From source (Go):**
```bash
go install github.com/The-17/agentsecrets/cmd/agentsecrets@latest
```

### First-Time Setup

```bash
# Create your account
agentsecrets init

# Create a project
agentsecrets project create my-app

# Add secrets
agentsecrets secrets set DATABASE_URL=postgresql://...
agentsecrets secrets set API_KEY=sk_live_...

# Or push existing .env
agentsecrets secrets push
```

### Use With AI

Tell your AI assistant:

> "I use AgentSecrets for secrets management. Pull my production secrets for the 'my-app' project before deploying."

The AI will run:
```bash
agentsecrets workspace switch production
agentsecrets project use my-app
agentsecrets secrets pull
# Your .env is ready, AI never saw the values
```

---

## Features

- **AI-Native**: Built specifically for AI-assisted development workflows
- **Zero-Knowledge**: AI manages secrets by name, never sees values
- **Universal**: Works with Python, Node, Go, Rust, Java, PHP, any language
- **Team-Ready**: Workspaces for collaboration, invite teammates
- **Secure**: X25519 + Fernet encryption, keys stored in system keychain
- **Fast**: Single binary, no runtime dependencies

---

## How It Works

### The Zero-Knowledge Architecture

```
┌─────────────┐
│ AI Assistant│ "Pull production secrets for my-app"
└──────┬──────┘
       │ Executes command (never sees values)
       ▼
┌─────────────┐
│agentsecrets │ 1. Fetches encrypted secrets from cloud
│    CLI      │ 2. Decrypts locally with your key
└──────┬──────┘ 3. Writes to .env file
       │
       ▼
┌─────────────┐
│  .env file  │ DATABASE_URL=postgresql://...
└─────────────┘ API_KEY=sk_live_...
       │
       ▼ (AI references by key, not value)
┌─────────────┐
│  Your App   │ process.env.DATABASE_URL
└─────────────┘
```

**What AI Knows**: "The app needs DATABASE_URL and API_KEY"  
**What AI Doesn't Know**: The actual values  

### Security Model

1. **Secrets encrypted** on your machine before upload
2. **Server stores** encrypted blobs (can't decrypt them)
3. **Your key** lives in system keychain (Keychain on Mac, Secret Service on Linux, Credential Manager on Windows)
4. **AI executes** commands but never reads `.env` file
5. **Zero-knowledge** maintained end-to-end

---

## Commands

### Authentication
```bash
agentsecrets init                    # Create account
agentsecrets login                   # Login to existing account
```

### Workspaces
```bash
agentsecrets workspace create "Team Name"     # Create workspace
agentsecrets workspace list                   # List all workspaces
agentsecrets workspace switch "Team Name"     # Switch workspace
agentsecrets workspace invite user@email.com  # Invite teammate
```

### Projects
```bash
agentsecrets project create my-app      # Create project
agentsecrets project list               # List projects
agentsecrets project use my-app         # Switch to project
```

### Secrets
```bash
agentsecrets secrets set KEY=value      # Set a secret
agentsecrets secrets get KEY            # Get a secret (you see it, AI doesn't)
agentsecrets secrets list               # List secret keys (not values)
agentsecrets secrets push               # Upload .env file
agentsecrets secrets pull               # Download to .env file
agentsecrets secrets remove KEY         # Remove a secret
```

---

## AI Integration

### Claude Skill

When using Claude with computer use, AgentSecrets skill teaches Claude to:
- Pull secrets before deployments
- Never display secret values
- Reference secrets by key name only
- Help manage multi-environment workflows

**Coming soon**: Official Claude skill in MCP registry

### ChatGPT

Add to custom instructions:
```
When I ask you to deploy or work with secrets, use AgentSecrets CLI.
Never ask me to paste secrets. Commands:
- agentsecrets secrets pull (load secrets)
- agentsecrets workspace switch <env> (change environment)
Reference secrets by key name only, never display values.
```

### GitHub Copilot

AgentSecrets works seamlessly in Copilot workflows. Copilot can suggest:
```javascript
// Load secrets from AgentSecrets
// Run: agentsecrets secrets pull
const apiKey = process.env.API_KEY;
```

---

## Use Cases

### Multi-Environment Deployment
```bash
# Staging
agentsecrets workspace switch staging
agentsecrets secrets pull
npm run deploy

# Production
agentsecrets workspace switch production
agentsecrets secrets pull
npm run deploy
```

### Team Onboarding
```bash
# New developer joins
agentsecrets login
agentsecrets project use team-app
agentsecrets secrets pull
# Ready to code, no asking teammates for credentials
```

### Microservices
```bash
# Each service has its own project
agentsecrets project use auth-service && agentsecrets secrets pull
agentsecrets project use api-gateway && agentsecrets secrets pull
agentsecrets project use payment-service && agentsecrets secrets pull
```

---

## Comparison

| Feature | AgentSecrets | 1Password | Vault | AWS Secrets | Doppler |
|---------|--------------|-----------|-------|-------------|---------|
| AI-Native | ✅ Built for it | ❌ | ❌ | ❌ | ❌ |
| Zero-Knowledge | ✅ Yes | ✅ Yes | ⚠️ Optional | ❌ No | ❌ No |
| Language-Agnostic | ✅ Universal binary | ⚠️ CLI + GUI | ✅ Yes | ⚠️ AWS-focused | ✅ Yes |
| Team Workspaces | ✅ Built-in | ✅ Vaults | ⚠️ Complex | ⚠️ IAM roles | ✅ Projects |
| Free Tier | ✅ Generous | ❌ Paid only | ✅ Open source | ⚠️ AWS costs | ⚠️ Limited |
| Setup Time | ⚡ 1 minute | ⏱️ 5 minutes | ⏱️ 15+ minutes | ⏱️ 30+ minutes | ⏱️ 10 minutes |

---

## Development Status

**Current**: Alpha / Active Development  
**Stability**: API may change  
**Production Ready**: Not yet, use at your own risk

We're building in public. Watch the repo for updates.

### Roadmap

- [x] Core CLI in Go
- [x] Workspaces & Projects
- [x] Secrets encryption
- [ ] Multi-platform binaries (macOS, Linux, Windows)
- [ ] Claude skill (MCP)
- [ ] ChatGPT integration
- [ ] Homebrew tap
- [ ] npm/pip wrappers
- [ ] Web dashboard
- [ ] Audit logs
- [ ] Secret rotation
- [ ] 1.0 release

---

## Architecture

Built with Go for universal compatibility:

- **Crypto**: X25519 (key exchange) + Fernet (symmetric encryption)
- **Keyring**: System keychain integration (keyring library)
- **API**: RESTful backend (coming from SecretsCLI infrastructure)
- **Distribution**: Single binary, ~5-10MB

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for deep dive.

---

## Contributing

We're building this in the open and would love your help!

- **Found a bug?** [Open an issue](https://github.com/The-17/agentsecrets/issues)
- **Have an idea?** [Start a discussion](https://github.com/The-17/agentsecrets/discussions)
- **Want to contribute?** Check [CONTRIBUTING.md](docs/CONTRIBUTING.md)

### Quick Contribution Guide

```bash
# Fork the repo, then:
git clone https://github.com/YOUR_USERNAME/agentsecrets
cd agentsecrets
go mod download
go run cmd/agentsecrets/main.go --help

# Make changes, test
go test ./...

# Submit PR
```

---

## Related Projects

- **[SecretsCLI](https://github.com/The-17/SecretsCLI)** - Original Python implementation
- **Coming**: Node.js SDK, Python SDK, Rust SDK

---

## Security

### Reporting Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Email: hello@theseventeen.co

We'll respond within 24 hours.

### Security Model

- Secrets encrypted client-side before upload
- Keys stored in OS keychain, never in plaintext
- Zero-knowledge: server can't decrypt your secrets
- TLS for all API communication
- Regular security audits (planned)

---

## FAQ

**Q: How is this different from SecretsCLI?**  
A: AgentSecrets is the Go rewrite of SecretsCLI, designed specifically for AI-assisted development. It's language-agnostic and AI-native.

**Q: Can I use this without AI?**  
A: Absolutely! It's a great secrets manager for any developer, with or without AI assistance.

**Q: Is it free?**  
A: Yes

**Q: What if the server gets hacked?**  
A: Your secrets are encrypted with your key. The server only has encrypted blobs it can't read.

**Q: Does this work with [language]?**  
A: Yes! AgentSecrets is a universal CLI that works with Python, Node, Go, Rust, Java, PHP, Ruby, and any other language.

**Q: How do I migrate from 1Password/Vault/etc?**  
A: Export your secrets to a `.env` file, then `agentsecrets secrets push`. Migration guides coming soon.

---

## Links

- **Website**: [agentsecrets.com](https://agentsecrets.com) (coming soon)
- **GitHub**: [github.com/The-17/agentsecrets](https://github.com/The-17/agentsecrets)
- **Docs**: [docs.agentsecrets.com](https://docs.agentsecrets.com) (coming soon)
- **Discord**: [discord.gg/agentsecrets](https://discord.gg/agentsecrets) (coming soon)

---

## License

MIT License - see [LICENSE](LICENSE) for details

---

## Credits

Built with ❤️ by [The Seventeen](https://github.com/The-17)

Powered by the same infrastructure as [SecretsCLI](https://github.com/The-17/SecretsCLI)

---

**Star this repo if you believe developers deserve better secrets management in the AI era** ⭐