# AgentSecrets

**Zero-Knowledge Credential Infrastructure for AI Agents, Humans, and Teams.**

A unified enforcement pipeline that stores, injects, governs, and audits credentials without ever letting them enter the agent's context. Agents execute tasks by referencing a key name, and they never hold, see, or receive the raw value.

[![License: MIT](https://img.shields.io/badge/License-MIT-green)]() [![Go Version](https://img.shields.io/badge/Go-1.x-00ADD8)]() [![Stars](https://img.shields.io/github/stars/The-17/agentsecrets)]()

**[Website](https://agentsecrets.tech) · [Docs](https://agentsecrets.tech/docs) · [Engineering Publication](https://engineering.theseventeen.co/series/building-agentsecrets)**


---

Credentials are the backbone of the modern world. Every database, API, and system we touch is protected by one thing: access. As software has become more autonomous, the layer that controls that access hasn't kept up.

An AI agent's capability is bounded entirely by the credentials it can reach, and giving it access to a value means accepting that the value can be leaked, whether through prompt injection, a logged trace, a malicious plugin, or a CVE in a dependency running in the same process. AgentSecrets exists to remove that assumption rather than manage around it.

## The Critical Difference

**Runtime retrieval (the common pattern).** The agent fetches or leases a credential, and the value enters agent memory.

```bash
export TOKEN=$(secrets lease github_token)
# The agent now holds sk_live_EXAMPLE... in memory
```

Once a value enters agent context, it can be extracted by prompt injection, exposed in logs or traces, or read by any tool, plugin, or dependency in the same process.

**Zero-knowledge injection (AgentSecrets).** The agent references a key name, and the value is resolved outside the agent and injected at the transport layer.

```bash
agentsecrets call --bearer GITHUB_TOKEN
# The agent referenced a name. It never received a value.
```

```
Secure store → agent retrieves sk_live_EXAMPLE... → value enters agent memory
                                                   → reachable by prompt injection
                                                   → readable by a malicious plugin
                                                   → exposed by a CVE
                                                   → captured in an LLM trace

OS keychain → proxy resolves in memory → value injected at transport layer
                                       → agent receives the API response only
                                       → value never entered agent context
                                       → nothing to steal, log, or extract
```

The agent can't be prompted to reveal a value it never held, and it can't be logged or stolen through a plugin, because it was structurally absent from every place an attack would look. That guarantee is architectural rather than policy-based. Read the full model in the [docs](https://agentsecrets.tech/docs).

## Architecture

AgentSecrets is an extensible host with one pluggable subsystem today:

| Layer | System | What It Solves |
|---|---|---|
| **Credential Infrastructure** | AgentSecrets (Host) | Agent credential theft and lifecycle management, covering six auth injection styles, client-side encryption (X25519, AES-256-GCM, Argon2id), SSRF protection, and response redaction. The server stores ciphertext it structurally cannot decrypt. |
| **Capability Bounding** | [Keychain-Auth (Subsystem)](https://github.com/The-17/keychain-auth) | Static, long-lived, over-privileged local credentials. OS keychain access is verified against the calling process's cryptographic hash, so only authorized binaries can resolve a credential, even from the same machine. |

On top of that sits agent identity and audit, where every execution is mapped to a cryptographically issued token and logged in a SHA-256 chain with no value field to leak, along with environments and teams, which support instant dev/staging/prod switching and sync secrets client-side via NaCl SealedBox so no plaintext ever touches the wire. Full detail is in the [docs](https://agentsecrets.tech/docs).

## Ecosystem

AgentSecrets connects to the tools you already use: MCP servers for Claude Desktop and Cursor, OpenClaw, environment-variable injection for any CLI tool, and an HTTP proxy that works with LangChain, CrewAI, and AutoGen. A Python SDK is available now, with a JS/TS version coming soon, and neither has a `get()` method, since there's no code path that should return a raw value. Full integration guides are in the [Integrations](https://agentsecrets.tech/docs/integrations/overview).

## Installation

```bash
# Homebrew (macOS / Linux)
brew install The-17/tap/agentsecrets

# npm
npm install -g @the-17/agentsecrets

# pip
pip install agentsecrets-cli

# Go (pin a version for supply chain security)
go install github.com/The-17/agentsecrets/cmd/agentsecrets@v3.0.0
```

## Troubleshooting & Self-Healing

If you encounter issues with credentials, binary registration, or the keychain daemon after an upgrade:

```bash
agentsecrets doctor
```

`agentsecrets doctor` verifies the local trust chain, checks daemon health, repairs registration mismatches, and re-verifies your installation automatically.

## Quick Start

```bash
agentsecrets init
agentsecrets project create my-agent

agentsecrets secrets set STRIPE_KEY=sk_live_EXAMPLE...
agentsecrets workspace allowlist add api.stripe.com

agentsecrets mcp install        # Claude Desktop + Cursor
agentsecrets proxy start        # any agent via HTTP proxy
```

## What This Looks Like in Practice

```
$ agentsecrets secrets diff
# In Cloud but missing in Local:
#   STRIPE_KEY

$ agentsecrets secrets pull
# Successfully synced cloud secrets and allowlist domains.

$ agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY
# {"object":"balance","available":[{"amount":420000,"currency":"usd"}]}

$ agentsecrets proxy logs --last 1
# 14:23:01  GET  api.stripe.com/v1/balance  STRIPE_KEY  200  245ms
```

The agent managed the entire workflow, and no credential value appeared at any step. The audit log has no value field, because there was no value to log.

## Where to Go Deeper

| Topic | What it covers |
|---|---|
| [Environments](https://agentsecrets.tech/docs/concepts/environments) & [Team Workspaces](https://agentsecrets.tech/docs/workspaces/overview) | Dev/staging/prod isolation, zero-knowledge team sync, onboarding without sharing plaintext |
| [Agent Identity](https://agentsecrets.tech/docs/concepts/agent-identity) & [Policies](https://agentsecrets.tech/docs/concepts/secret-policies) | Cryptographic agent tokens, per-agent allow/deny lists, secret-level domain and method rules, interactive approval flow |
| [Auth Injection Styles](https://agentsecrets.tech/docs/proxy/injection-styles) | All six injection modes: bearer, header, query, basic, JSON body, and form field |
| [Zero-Trust Proxy Pipeline](https://agentsecrets.tech/docs/proxy/overview) | The full request pipeline, including allowlisting, capability checks, SSRF protection, and response redaction |
| [Encryption Model](https://agentsecrets.tech/docs/security/encryption) | X25519 key exchange, AES-256-GCM, Argon2id, OS keychain storage, and SHA-256 audit chaining |
| [Build on AgentSecrets](https://agentsecrets.tech/docs/sdk/overview) | Python SDK, zero-knowledge MCP template, and the JS/TS SDK (coming soon) |
| [Full Command Reference]([https://agentsecrets.tech/docs](https://agentsecrets.tech/docs/cli/account)) | Every subcommand across account, workspace, project, environment, secrets, proxy, and audit |

## Roadmap · Security · Contributing

- **Build logs:** see the [engineering publication](https://engineering.theseventeen.co/series/building-agentsecrets) to read the story.
- **Security:** found a vulnerability? See [SECURITY.md](SECURITY.md) for responsible disclosure.
- **Contributing:** see [CONTRIBUTING.md](CONTRIBUTING.md) to get set up locally.
- **Self-hosting:** the open-source server backend that powers sync, workspaces, and telemetry is at [github.com/The-17/agentsecrets-server](https://github.com/The-17/agentsecrets-server).

## License

AgentSecrets is open-source software licensed under the [MIT License](LICENSE).

