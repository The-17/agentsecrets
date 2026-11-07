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
pip install agentsecrets-cli
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

By default, new projects use the `development` environment. You can isolate your secrets by switching to `staging` or `production` at any time:

```bash
agentsecrets environment switch staging
```
*(Note: Do not edit `.agent/workflows/agentsecrets.md` directly to change environments, the active environment is handled automatically by the CLI context for both you and your AI).*

---

## 3. Store Secrets

Values are encrypted client-side before leaving your machine:

```bash
agentsecrets secrets set STRIPE_KEY            # prompts; value stays out of shell history
agentsecrets secrets set DATABASE_URL          # same, for connection strings
agentsecrets secrets set OPENAI_KEY --generate # or mint a random value, never shown
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
14:23:01  * OK    GET     api.stripe.com/v1/balance        STRIPE_KEY   bearer  200     -       245ms
```

---

## Troubleshooting

Something not working or hit a daemon authorization denial? Run:

```bash
agentsecrets doctor
```

The doctor inspects the full local trust chain, repairs authorization mismatches, and re-verifies your installation.

---

## Cloud mode in production (zero config)

Moving from local to cloud is **one decision, set once by the platform** — not a
flag on every command. (Plan: [v4 Identity Rebuild](https://artifacts.theseventeen.co/artifacts/11f9d411-df0c-40e9-a0e4-e011f2367fac).)

### The two environment variables

Both reach the binary because the wrapper inherits the environment:

| Variable | Value | Purpose |
| --- | --- | --- |
| `AGENTSECRETS_MODE` | `cloud` | Select cloud resolution. No `agentsecrets mode cloud` command, no writable `~/.agentsecrets`, no config file in the image. |
| `AGENTSECRETS_TOKEN` | a workload token | Authenticates the cloud resolver. Prefer `AGENTSECRETS_TOKEN_FILE` to keep the token out of the process list. |

### What happens at boot

1. **No GitHub fetch, no writable home.** The Go binary ships inside the wheel/package (Phase 1), so it is already on disk. Nothing is downloaded and nothing is written to `~/.agentsecrets` at startup.
2. **Mode is selected from the environment.** `agentsecrets` reads `AGENTSECRETS_MODE=cloud` (highest env precedence) and resolves through the cloud resolver. No `mode` command and no config file are required.
3. **Secrets are injected, the token is not.** `agentsecrets env -- <cmd>` resolves secrets via `POST /api/workloads/env/`, injects them into the child process, and execs it. The child receives the secrets; it never receives `AGENTSECRETS_TOKEN`.
4. **Single-request override still works.** `agentsecrets call --cloud` forces cloud for one call on a local machine.

### Run examples

Copy-ready examples for every surface live in [`docs/deploy-examples/`](deploy-examples/).
Every example uses the **PATH-independent** command form so it works the moment
the package is installed, with no extra PATH setup (see Boot-path availability
below):

- `Dockerfile` — `ENV AGENTSECRETS_MODE=cloud`, `ENTRYPOINT ["python", "-m", "agentsecrets", "env", "--"]`
- `docker-compose.yml` — `command: ["npx", "agentsecrets", "env", "--", "node", "server.js"]`
- `vercel.json` — `env.AGENTSECRETS_MODE` and `devCommand: "npx agentsecrets env -- npm run dev"`
- `github-actions.yml` — job `env` + `python -m agentsecrets env -- python deploy.py`

### Boot-path availability

The `agentsecrets` command reaches the binary two ways, and the examples pick
the one that does not depend on the console script being on `PATH`:

- **PyPI.** `pip install agentsecrets-cli` installs a `agentsecrets` console
  script (on `PATH` only when the install location is on `PATH`, e.g. a venv's
  `bin/` or `/usr/local/bin`). It also ships a `python -m agentsecrets` module
  entry point that resolves the package from the active interpreter's
  `site-packages`, so `python -m agentsecrets ...` works even from a `--user`
  install or a minimal container `PATH`.
- **npm.** `npm install @the-17/agentsecrets` links the launcher into
  `node_modules/.bin`, which is on `PATH` only inside `npm run`/`npm exec`. The
  examples invoke it as `npx agentsecrets`, which resolves the local bin, or via
  the explicit `node_modules/.bin/agentsecrets` path.

Either way, the bundled Go binary is found by the wrapper (Phase 1), so no
GitHub fetch and no writable `~/.agentsecrets` are needed at boot.

### Verify

`scripts/verify-cloud-env.sh` runs `agentsecrets env --` inside an `unshare -Urmn`
namespace with `AGENTSECRETS_MODE=cloud` set and asserts cloud selection, the
captured injected-env count, and the exit code. A live success run needs a real
`AGENTSECRETS_TOKEN` and network egress; offline it proves the selection path and
fail-closed behavior.

`scripts/verify-boot-path.sh` proves the command is callable at boot across every
surface — the `agentsecrets` console script, `python -m agentsecrets`, the npm
`node_modules/.bin` link, and `npx` — and that the module form still resolves
when the console script is not on `PATH`.

## Next Steps

- [Command Reference](commands/) — full reference for every subcommand
- [Proxy & MCP](PROXY.md) — deep dive into proxy authentication styles
- [Architecture](ARCHITECTURE.md) — how the encryption model works
- [Contributing](CONTRIBUTING.md) — how to contribute