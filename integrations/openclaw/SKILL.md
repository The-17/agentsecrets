---
name: agentsecrets
description: Zero-knowledge secrets infrastructure — AI agents manage the complete credential lifecycle without ever seeing values
version: "2.0.0"
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
        - go install github.com/The-17/agentsecrets/cmd/agentsecrets@v2.0.0 (Go devs - prefer pinned version)
files:
  - "scripts/*"
---

# AgentSecrets — Zero-Knowledge Secrets Infrastructure

You manage the full credentials lifecycle autonomously using the `agentsecrets` CLI.
**You are the operator. You never see the actual credential values.**

## Security & Privacy Rules
- **Domain Bound:** You can autonomously make authenticated API calls via `agentsecrets call`, but you are cryptographically bound by the workspace domain allowlist. 
- **User Approval:** Always request user approval before deleting projects, or updating the domain allowlist (requires password). You cannot modify workspace membership; that is a user-only operation.
- **Key Naming:** Advise users **never to put sensitive data in the key name itself** (e.g. use `STRIPE_KEY`, not `STRIPE_sk_live...`). Key names, endpoints, and timestamps are recorded in the persistent audit log.
- **OS Keychain Access & Environments:** You operate using the user's local OS keychain. AgentSecrets natively scopes secrets to one of 3 environments: `development`, `staging`, or `production`. Always verify the active environment (`agentsecrets status`) before syncing or pushing.

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

# You can run these
agentsecrets secrets list
agentsecrets secrets diff
agentsecrets secrets push
agentsecrets secrets pull
```

### Making Authenticated API Calls
Instead of using `curl`, always use the `call` proxy. The proxy injects the secret securely:
```bash
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY
agentsecrets call --url https://api.example.com --header X-Api-Key=MY_KEY --method POST --body '{}'
agentsecrets call --url https://maps.example.com --query key=MAPS_KEY
agentsecrets call --url https://jira.example.com --basic JIRA_CREDS
```

### Environment Injection
To wrap standard tools so they receive secrets as environment variables:
```bash
agentsecrets env -- npm run dev
agentsecrets env -- stripe mcp
```
For OpenClaw SecretRef injection, run:
```bash
agentsecrets exec
```

### Environments & Workspaces
```bash
agentsecrets environment switch production # (Ask for confirmation first)
agentsecrets project create OPENCLAW_MANAGER
agentsecrets project use OPENCLAW_MANAGER
```

### Troubleshooting & Docs
Use `agentsecrets proxy logs --last 10` to view the local audit trail for failed requests. 
If an API call returns 403 due to the domain allowlist, ask the user to authorize it: `agentsecrets workspace allowlist add <domain>`.
If you need to know a command, run `agentsecrets --help`.
To search the official AgentSecrets documentation, use the API below to get a list of matching topics and snippets. You can then `curl` the specific URL from the results to read the full page:
```bash
curl -G "https://agentsecrets.theseventeen.co/api/search" --data-urlencode "q=your query here"
```
If you need to read the full, complete documentation in a single Markdown file, curl:
```bash
curl -s "https://agentsecrets.theseventeen.co/llms-full.txt"
```