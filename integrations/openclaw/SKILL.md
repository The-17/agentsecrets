---
name: agentsecrets
description: Zero-knowledge secrets infrastructure — AI agents manage the complete credential lifecycle without ever seeing values
version: "3.0"
tags: [security, credentials, api, secrets, mcp, zero-knowledge]
homepage: https://github.com/The-17/agentsecrets
registry: https://clawhub.ai/SteppaCodes/agentsecrets
metadata:
  clawdbot:
    summary: Zero-knowledge secrets infrastructure — the agent manages credentials autonomously without ever seeing values
    author: The Seventeen
    license: MIT
requires:
  env:
    - name: AGENTSECRETS_INSTALLED
      description: Set to "true" once agentsecrets is installed (auto-detected)
      required: false
  binaries:
    - name: agentsecrets
      description: The AgentSecrets CLI binary
      install: |
        - npx @the-17/agentsecrets (Run without install)
        - brew install The-17/tap/agentsecrets (macOS/Linux)
        - pip install agentsecrets-cli (Python/Universal)
        - go install github.com/The-17/agentsecrets/cmd/agentsecrets@v3.0.0 (Go devs - prefer pinned version)
files:
  - "scripts/*"
---

# AgentSecrets — Zero-Knowledge Secrets Infrastructure

You manage the full credentials lifecycle autonomously using the `agentsecrets` CLI or Model Context Protocol (MCP) server.
**You are the operator. You never see the actual credential values.**

## Security & Privacy Rules (with Native Mitigations)

> [!WARNING]
> **Outbound Data Exfiltration Risk & Allowlist Mitigation**:
> Although you can autonomously trigger API calls through the proxy, AgentSecrets strictly mitigates exfiltration risks via the **Workspace Domain Allowlist**. Outbound requests are blocked by default unless the destination domain is explicitly authorized. Only workspace administrators can alter the allowlist (which requires local password verification).
>
> **Rogue credential modification & Password Mitigation**:
> Unsupervised scripts or agents are prevented from tampering with critical environments. Creating, modifying, or deleting secrets in the `production` environment (or globally across all environments) requires **Local Password Verification**.
>
> **Plaintext Exposure & Zero-Knowledge Enforcement**:
> You must **never** attempt to retrieve or display plaintext credential values. The `agentsecrets secrets get` command is strictly restricted for agents. OS Keychain storage is further isolated by the `keychain-auth` daemon's **Process Hash Verification** to prevent process hijacking.
>
> **Outbound Request Auditing**:
> All outbound requests and enforcement outcomes are automatically recorded in the local SQLite database (`~/.agentsecrets/audit.db`). The forensic log is cryptographically chain-hashed (`chain_hash = sha256(prev_id + current_id + created_at)`) to guarantee log immutability and non-repudiation.

## Core Workflow Commands
Always start by verifying context:
```bash
agentsecrets status # Shows workspace, project, environment
agentsecrets secrets list # Lists available keys
```

If not initialized or logged out, tell the user to run `agentsecrets login`. For new projects, run `agentsecrets init --storage-mode 1`.

### Managing Secrets
```bash
# User runs this in their terminal (do not ask them to paste it in chat)
agentsecrets secrets set KEY_NAME=value

# You can run these (Never use 'get' — agents must operate without seeing credentials)
agentsecrets secrets list
agentsecrets secrets diff
agentsecrets secrets push
agentsecrets secrets pull
```

### Making Authenticated API Calls (Proxy Engine)
Instead of using `curl`, always use the `call` proxy. The proxy injects the secret securely:
```bash
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY
agentsecrets call --url https://api.example.com --header X-Api-Key=MY_KEY --method POST --body '{}'
agentsecrets call --url https://maps.example.com --query key=MAPS_KEY
agentsecrets call --url https://jira.example.com --basic JIRA_CREDS
```
*Note: Outbound requests are protected by DNS rebinding defense, SSRF blocking of private/loopback IPs (bypass locally with `--allow-local-http`), and a pre-shared session token header `X-AS-Session-Token` injected automatically by the CLI.*

### Model Context Protocol (MCP) Server
To use the native MCP server inside Cursor or Claude Desktop, you can run or instruct the user to configure:
```bash
agentsecrets mcp install   # Automatically registers tools with local editors
agentsecrets mcp serve     # Exposes tools: api_call, list_keys, check_key, etc.
```

### Environment Injection
To wrap standard tools so they receive secrets as environment variables:
```bash
agentsecrets env -- npm run dev
agentsecrets env -- stripe mcp
```
> [!WARNING]
> **Environment Leak Warning**: Injecting credentials as environment variables into child processes is convenient but carries the risk of leaking secrets to child command logs, error telemetry, core dumps, or inherited environments. Prefer using the `api_call` or proxy `call` methods wherever possible.

For OpenClaw SecretRef injection, run:
```bash
agentsecrets exec
```

### Environments & Workspaces
```bash
agentsecrets environment switch production # (Requires password verification)
agentsecrets project create OPENCLAW_MANAGER
agentsecrets project use OPENCLAW_MANAGER
```

### Audit Log & Forensic Verification
```bash
agentsecrets log               # View recent calls (outcome, domains, keys used)
agentsecrets log verify        # Recalculates and verifies cryptographic chain integrity
agentsecrets log replay <id>   # Replay the active credential firewall state for an audit
```

### Troubleshooting & Docs
Use `agentsecrets proxy logs --last 10` to view the local audit trail for failed requests. 
If an API call returns 403 due to the domain allowlist, ask the user to authorize it: `agentsecrets workspace allowlist add <domain>`.
If you need to know a command, run `agentsecrets --help`.
To search the official AgentSecrets documentation, use the API below to get a list of matching topics and snippets. You can then `curl` the specific URL from the results to read the full page:
```bash
curl -G "https://agentsecrets.tech/api/search" --data-urlencode "q=your query here"
```
If you need to read the full, complete documentation in a single Markdown file, curl:
```bash
curl -s "https://agentsecrets.tech/llms-full.txt"
```