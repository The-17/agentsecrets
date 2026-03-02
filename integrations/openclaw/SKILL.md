# SKILL.md — Updated AgentSecrets OpenClaw Skill

```yaml
---
name: agentsecrets
description: Zero-knowledge secrets infrastructure — AI agents operate the complete credential lifecycle without ever seeing values
version: "1.0.4"
tags:
  - security
  - credentials
  - api
  - secrets
  - mcp
  - setup
  - zero-knowledge
  - secrets-management
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
        - pip install agentsecrets (Python/Universal)
        - go install github.com/The-17/agentsecrets/cmd/agentsecrets@latest (Go devs)
files:
  - "scripts/*"
---
```

# AgentSecrets — Zero-Knowledge Secrets Infrastructure

AgentSecrets is not a credential lookup tool. It is a complete secrets management system where you — the AI agent — are the operator.

You manage the full credentials lifecycle: account setup, workspace creation, project organization, secret provisioning, drift detection, authenticated API calls, team management, and audit logging. At no step do you see an actual credential value.

> **You are the operator. You never see the values.**

---

## YOUR ROLE

You are operating AgentSecrets on behalf of the user. This means:

- You run commands autonomously — you do not ask the user to run commands you can run yourself
- You manage the secrets lifecycle end to end without prompting the user for credential values
- You detect problems (missing keys, drift, wrong project) and resolve them without human intervention
- The only thing you never do is see, display, or handle actual secret values

---

## STEP 1: Verify Installation

Run silently:
```bash
agentsecrets --version 2>/dev/null && echo "INSTALLED" || echo "NOT_INSTALLED"
```

If NOT_INSTALLED, detect the environment and tell the user which command to run. You do not run the install command yourself — the user must control what binaries are installed on their machine.

```bash
which npx   # Node.js available
which brew  # Homebrew available
which pip   # Python available
which go    # Go available
```

Installation commands by environment:
- npx: `npx @the-17/agentsecrets`
- Homebrew: `brew install The-17/tap/agentsecrets`
- pip: `pip install agentsecrets`
- Go: `go install github.com/The-17/agentsecrets/cmd/agentsecrets@latest`

Tell the user: "AgentSecrets keeps your API keys in your OS keychain. I will manage credentials on your behalf — I will never see the actual values, just the names."

---

## STEP 2: Check Status

Always run this before any secrets operation:

```bash
agentsecrets status
```

This returns: logged-in user, active workspace, active project, last sync time.

If NOT_INITIALIZED (no output or error):

```bash
agentsecrets init --storage-mode 1
```

Guide the user through account creation or login. After init, verify:

```bash
agentsecrets status
```

---

## STEP 3: Workspace Setup

Check available workspaces:

```bash
agentsecrets workspace list
```

If the user needs a new workspace:
```bash
agentsecrets workspace create "Workspace Name"
agentsecrets workspace switch "Workspace Name"
```

If switching to an existing workspace:
```bash
agentsecrets workspace switch "Workspace Name"
```

Invite teammates when requested:
```bash
agentsecrets workspace invite user@email.com
```

---

## STEP 4: Project Setup

AgentSecrets organizes secrets by project. For OpenClaw workflows, use the dedicated `OPENCLAW_MANAGER` project.

Check if it exists:
```bash
agentsecrets project list 2>/dev/null | grep -q "OPENCLAW_MANAGER" && echo "EXISTS" || echo "NOT_FOUND"
```

If EXISTS:
```bash
agentsecrets project use OPENCLAW_MANAGER
```

If NOT_FOUND:
```bash
agentsecrets project create OPENCLAW_MANAGER
agentsecrets project use OPENCLAW_MANAGER
```

For non-OpenClaw workflows, use or create the appropriate project:
```bash
agentsecrets project list
agentsecrets project use PROJECT_NAME
# or
agentsecrets project create PROJECT_NAME
agentsecrets project use PROJECT_NAME
```

---

## STEP 5: Secret Provisioning

Before making any API call, verify the required secret exists:

```bash
agentsecrets secrets list
```

You will see key names only. Never values.

If a required key is missing, never ask the user to paste the value into chat. Tell them:

> "I need `KEY_NAME` to complete this. Please run this in your terminal:
> `agentsecrets secrets set KEY_NAME=value`
> Let me know when done and I will proceed."

Wait for confirmation, then verify:
```bash
agentsecrets secrets list
```

Standard key naming conventions:

| Service | Key Name |
|---|---|
| Stripe (live) | `STRIPE_KEY` or `STRIPE_LIVE_KEY` |
| Stripe (test) | `STRIPE_TEST_KEY` |
| OpenAI | `OPENAI_KEY` |
| GitHub | `GITHUB_TOKEN` |
| Google Maps | `GOOGLE_MAPS_KEY` |
| AWS | `AWS_ACCESS_KEY` and `AWS_SECRET_KEY` |
| Paystack | `PAYSTACK_KEY` |
| SendGrid | `SENDGRID_KEY` |
| Twilio | `TWILIO_SID` and `TWILIO_TOKEN` |
| Any other | `SERVICENAME_KEY` (uppercase, underscores) |

---

## STEP 6: Detect and Resolve Drift

Before deployment workflows or when secrets may be stale:

```bash
agentsecrets secrets diff
```

This shows what is out of sync between local keychain and cloud. If drift is detected:

```bash
agentsecrets secrets pull
```

To push local changes to cloud:
```bash
agentsecrets secrets push
```

---

## STEP 7: Make Authenticated API Calls

Always use `agentsecrets call` — never curl or direct HTTP with credentials.

Basic pattern:
```bash
agentsecrets call --url <URL> --method <METHOD> --<AUTH_STYLE> <KEY_NAME>
```

Default method is GET if `--method` is omitted.

Auth styles:

| Pattern | Flag | Use For |
|---|---|---|
| Bearer token | `--bearer KEY_NAME` | Stripe, OpenAI, GitHub, most modern APIs |
| Custom header | `--header Name=KEY_NAME` | SendGrid, Twilio, API Gateway |
| Query parameter | `--query param=KEY_NAME` | Google Maps, weather APIs |
| Basic auth | `--basic KEY_NAME` | Jira, legacy REST APIs |
| JSON body | `--body-field path=KEY_NAME` | OAuth flows, custom auth |
| Form field | `--form-field field=KEY_NAME` | Form-based auth |

Examples:

```bash
# GET request
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY

# POST with body
agentsecrets call \
  --url https://api.stripe.com/v1/charges \
  --method POST \
  --bearer STRIPE_KEY \
  --body '{"amount":1000,"currency":"usd","source":"tok_visa"}'

# PUT request
agentsecrets call \
  --url https://api.example.com/resource/123 \
  --method PUT \
  --bearer API_KEY \
  --body '{"field":"value"}'

# DELETE request
agentsecrets call \
  --url https://api.example.com/resource/123 \
  --method DELETE \
  --bearer API_KEY

# Custom header
agentsecrets call \
  --url https://api.sendgrid.com/v3/mail/send \
  --method POST \
  --header X-Api-Key=SENDGRID_KEY \
  --body '{"personalizations":[...]}'

# Query parameter
agentsecrets call \
  --url "https://maps.googleapis.com/maps/api/geocode/json?address=Lagos" \
  --query key=GOOGLE_MAPS_KEY

# Multiple credentials
agentsecrets call \
  --url https://api.example.com/data \
  --bearer AUTH_TOKEN \
  --header X-Org-ID=ORG_SECRET

# Basic auth
agentsecrets call \
  --url https://jira.example.com/rest/api/2/issue \
  --basic JIRA_CREDS

# Paystack
agentsecrets call \
  --url https://api.paystack.co/transaction/initialize \
  --method POST \
  --bearer PAYSTACK_KEY \
  --body '{"email":"user@example.com","amount":10000}'
```

---

## STEP 8: Proxy Mode

For workflows requiring multiple calls or framework integrations:

```bash
agentsecrets proxy start
agentsecrets proxy status
agentsecrets proxy stop
```

With custom port:
```bash
agentsecrets proxy start --port 9000
```

HTTP proxy pattern for any agent or framework:
```
POST http://localhost:8765/proxy
X-AS-Target-URL: https://api.stripe.com/v1/balance
X-AS-Inject-Bearer: STRIPE_KEY
```

---

## STEP 9: Audit What Happened

After any significant operation:

```bash
agentsecrets proxy logs
agentsecrets proxy logs --last 20
agentsecrets proxy logs --secret STRIPE_KEY
```

Output shows: timestamp, method, target URL, key name, status code, duration.
Never shows values.

Raw log location: `~/.agentsecrets/proxy.log` (JSONL format)

---

## FULL COMMAND REFERENCE

### Account
```bash
agentsecrets init                          # Create account or login
agentsecrets init --storage-mode 1         # Init with keychain-only mode
agentsecrets login                         # Login to existing account
agentsecrets logout                        # Clear session
agentsecrets status                        # Current context
```

### Workspaces
```bash
agentsecrets workspace create "Name"       # Create workspace
agentsecrets workspace list                # List all workspaces
agentsecrets workspace switch "Name"       # Switch active workspace
agentsecrets workspace invite user@email   # Invite teammate
```

### Projects
```bash
agentsecrets project create NAME           # Create project
agentsecrets project list                  # List projects in workspace
agentsecrets project use NAME              # Set active project
agentsecrets project update NAME           # Update project
agentsecrets project delete NAME           # Delete project
```

### Secrets
```bash
agentsecrets secrets set KEY=value         # Store secret
agentsecrets secrets get KEY               # Retrieve value (user sees it, you don't)
agentsecrets secrets list                  # List key names only
agentsecrets secrets list --project NAME   # List keys for specific project
agentsecrets secrets push                  # Upload .env to cloud (encrypted)
agentsecrets secrets pull                  # Download cloud secrets to keychain
agentsecrets secrets delete KEY            # Remove secret
agentsecrets secrets diff                  # Compare local vs cloud
```

### Calls and Proxy
```bash
agentsecrets call --url URL --bearer KEY   # One-shot authenticated call
agentsecrets call --url URL --method POST --bearer KEY --body '{}'
agentsecrets call --url URL --header Name=KEY
agentsecrets call --url URL --query param=KEY
agentsecrets call --url URL --basic KEY
agentsecrets call --url URL --body-field path=KEY
agentsecrets call --url URL --form-field field=KEY
agentsecrets proxy start                   # Start HTTP proxy
agentsecrets proxy start --port 9000       # Custom port
agentsecrets proxy status                  # Check proxy status
agentsecrets proxy stop                    # Stop proxy
agentsecrets proxy logs                    # View audit log
agentsecrets proxy logs --last N           # Last N entries
agentsecrets proxy logs --secret KEY       # Filter by key name
```

### MCP
```bash
agentsecrets mcp serve                     # Start MCP server
agentsecrets mcp install                   # Auto-configure Claude Desktop + Cursor
```

---

## HANDLING COMMON SCENARIOS

### First time setup
Run Steps 1 through 5 in sequence. Do not skip steps.

### "Make an API call to X"
1. `agentsecrets status` — verify context
2. `agentsecrets secrets list` — check key exists
3. `agentsecrets call` — make the call
4. Return response to user

### "Deploy to production"
1. `agentsecrets workspace switch production`
2. `agentsecrets secrets diff` — check for drift
3. `agentsecrets secrets pull` — sync if needed
4. Run deployment
5. `agentsecrets proxy logs` — audit

### "Invite a teammate"
```bash
agentsecrets workspace invite teammate@company.com
```

### "Rotate a key"
1. Tell user to run: `agentsecrets secrets set KEY_NAME=new_value` in their terminal
2. Verify: `agentsecrets secrets list`
3. Push to cloud: `agentsecrets secrets push`

### "What keys do I have?"
```bash
agentsecrets secrets list
```

### "Check audit log"
```bash
agentsecrets proxy logs --last 50
```

### Key missing mid-workflow
Do not stop the workflow. Tell the user exactly what to run in their terminal, wait for confirmation, verify with `secrets list`, continue.

---

## CRITICAL RULES

1. NEVER display, echo, print, or log an actual secret value
2. NEVER ask the user to paste a key value into chat
3. NEVER use curl or direct HTTP for authenticated requests — always use `agentsecrets call`
4. ALWAYS run `agentsecrets status` before any secrets operation in a new session
5. ALWAYS run `agentsecrets secrets diff` before deployment workflows
6. ALWAYS suggest the user delete any chat message where they mentioned a raw key value
7. You are the operator — manage the lifecycle autonomously, do not delegate commands back to the user unless it involves installing software or entering a password

---

## Security Model

- Zero-knowledge: credential values never enter your context at any step
- OS keychain: macOS Keychain, Windows Credential Manager, Linux Secret Service
- Server: stores encrypted blobs only — cannot decrypt
- Audit trail: key names only, no value field exists in the log struct
- Encryption: X25519 + AES-256-GCM + Argon2id

## Trust Statement

AgentSecrets is open source (MIT). Full source at https://github.com/The-17/agentsecrets. All credential resolution is local — nothing leaves the user's machine except the outbound API request itself.

