# agentsecrets env

> Inject secrets from the OS keychain as environment variables into a child process.

## Usage

```bash
agentsecrets env -- <command> [args...]
```

The `--` separator is required. Everything after it is passed verbatim as the command and its arguments.

---

## Makefile Integration

The lowest-friction way to use `agentsecrets env` in a project is to define a `RUN` variable at the top of your Makefile and prefix commands with it. This way you type `make dev` and not `agentsecrets env -- npm run dev`.

### Pattern 1: `RUN` prefix variable (recommended)

Define once, use everywhere:

```makefile
RUN := agentsecrets env --

dev:
	$(RUN) npm run dev

test:
	$(RUN) npm test

migrate:
	$(RUN) python manage.py migrate

server:
	$(RUN) python manage.py runserver

worker:
	$(RUN) celery -A myapp worker --loglevel=info

build:
	$(RUN) go build ./...
```

Now `make dev` runs with secrets injected. The `RUN` variable acts as a transparent prefix.

**Bonus:** You can override `RUN` from the shell to strip injection entirely (useful for debugging without the keychain):

```bash
make dev RUN=           # runs: npm run dev (no injection)
make dev               # runs: agentsecrets env -- npm run dev
```

### Pattern 2: Named targets (explicit)

If you prefer each target to be completely self-contained:

```makefile
dev:
	agentsecrets env -- npm run dev

test:
	agentsecrets env -- pytest

migrate:
	agentsecrets env -- python manage.py migrate

shell:
	agentsecrets env -- python manage.py shell
```

### Django project example (full Makefile)

```makefile
RUN := agentsecrets env --

.PHONY: dev test migrate shell celery

dev:
	$(RUN) python manage.py runserver

test:
	$(RUN) python manage.py test

migrate:
	$(RUN) python manage.py migrate

shell:
	$(RUN) python manage.py shell

celery:
	$(RUN) celery -A myapp worker --loglevel=info

# Run without injection (for debugging env setup)
dev-raw:
	python manage.py runserver
```

`make dev`, `make test`, `make migrate` — that's it. No `.env` files, no `export`, no `source`.

---

## How It Works

`agentsecrets env` is a **process wrapper**. It resolves all secrets for the active project from the OS keychain, then spawns the specified command as a child process with those secrets available in its environment.

Mechanically:

1. Reads the active project from `.agentsecrets/project.json`
2. Calls `keyring.GetAllProjectSecrets(projectID)` — pulls all key/value pairs from the OS keychain for that project
3. Builds the environment for the child process: **current process env + injected secrets** (project secrets override on conflict)
4. Spawns the child via `exec.Command`, with `stdin`, `stdout`, and `stderr` wired straight through — no buffering, no interception
5. Forwards `SIGINT` and `SIGTERM` to the child process (so `Ctrl+C` works exactly as expected)
6. Exits with the child's exact exit code

The parent process (`agentsecrets`) never uses the secret values — it only passes them directly into the child's environment at spawn time. Nothing is written to disk. When the child exits, the secrets are gone.

---

## Examples

### Python / Django

Django reads credentials from environment variables. Instead of putting secrets in `.env` files, inject them directly from the keychain:

```bash
# Run Django development server
agentsecrets env -- python manage.py runserver

# Run migrations (reads DATABASE_URL or DB_* vars from env)
agentsecrets env -- python manage.py migrate

# Django shell with secrets available
agentsecrets env -- python manage.py shell

# Celery worker
agentsecrets env -- celery -A myapp worker --loglevel=info

# Custom management command
agentsecrets env -- python manage.py send_newsletter
```

Your Django `settings.py` works without changes:

```python
# settings.py — reads from env as normal
import os

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ["DB_NAME"],
        "USER": os.environ["DB_USER"],
        "PASSWORD": os.environ["DB_PASSWORD"],  # injected by agentsecrets env
        "HOST": os.environ["DB_HOST"],
        "PORT": os.environ.get("DB_PORT", "5432"),
    }
}

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]   # injected by agentsecrets env
STRIPE_SECRET_KEY = os.environ["STRIPE_KEY"]   # injected by agentsecrets env
```

As long as the key names in `agentsecrets secrets list` match what `os.environ` reads, it works transparently.

### Node.js / Express

```bash
# Dev server (process.env.* available throughout)
agentsecrets env -- node server.js
agentsecrets env -- npm run dev
agentsecrets env -- npx ts-node src/index.ts

# Next.js
agentsecrets env -- npx next dev

# Prisma migrations
agentsecrets env -- npx prisma migrate dev
```

```js
// server.js — reads from process.env as normal
const stripe = require('stripe')(process.env.STRIPE_KEY);  // injected
const db = require('./db')(process.env.DATABASE_URL);       // injected
```

### Stripe CLI

Stripe CLI reads `STRIPE_API_KEY` from the environment:

```bash
# Start Stripe MCP server
agentsecrets env -- stripe mcp

# Forward webhook events to local server
agentsecrets env -- stripe listen --forward-to localhost:3000/webhooks

# Trigger a test event
agentsecrets env -- stripe trigger payment_intent.created
```

### Go

```bash
# Run binary
agentsecrets env -- ./myserver

# Run tests that hit real APIs
agentsecrets env -- go test ./pkg/payments/...
```

Inside Go, `os.Getenv("STRIPE_KEY")` reads from the injected environment exactly as expected.

### Shell / Scripts

```bash
# A script that sources no .env files — reads from env directly
agentsecrets env -- ./scripts/deploy.sh

# Docker Compose (picks up env vars from the shell)
agentsecrets env -- docker-compose up

# Verify which secrets are visible to the child
agentsecrets env -- printenv | grep STRIPE
agentsecrets env -- printenv DB_URL
```

### Claude Desktop / MCP Config

Wrap native MCP servers so they receive secrets from the keychain:

```json
{
  "mcpServers": {
    "stripe": {
      "command": "agentsecrets",
      "args": ["env", "--", "stripe", "mcp"]
    }
  }
}
```

---

## vs. `agentsecrets call`

| | `agentsecrets call` | `agentsecrets env` |
|---|---|---|
| **Use for** | One-shot HTTP API calls | Processes that read from `os.environ` |
| **How** | Proxy resolves + injects at transport layer | Secret values injected into child process environment |
| **Scope** | Single request | Entire process lifetime |
| **Frameworks** | Any agent via proxy or MCP | Django, Node.js, Stripe CLI, Go binaries, shell scripts |
| **Audit** | Per-request log with method, URL, status | Single log entry with key names and command |

Use `agentsecrets call` when you want the agent to make a specific authenticated API call.  
Use `agentsecrets env` when you're running a server, script, or CLI tool that manages its own HTTP calls.

---

## Output

```
ℹ Injecting 9 secrets: STRIPE_KEY + 8 more
```

For a single secret:

```
ℹ Injecting 1 secret: STRIPE_KEY
```

The output goes to stderr and doesn't interfere with the child process's stdout.

---

## Exit Codes

`agentsecrets env` passes the child's exit code through transparently:

```bash
agentsecrets env -- python manage.py test
echo $?  # exit code from Django test runner, not from agentsecrets
```

This means it works correctly in CI/CD pipelines — a failing test suite exits non-zero and the pipeline fails as expected.

---

## Audit Log

Every `agentsecrets env` invocation writes to `~/.agentsecrets/proxy.log`:

```json
{
  "timestamp": "2026-03-03T22:00:00Z",
  "method": "ENV",
  "target_url": "python manage.py runserver",
  "secret_keys": ["DB_PASSWORD", "STRIPE_KEY", "DJANGO_SECRET_KEY"],
  "auth_styles": ["env_inject"],
  "status": "OK",
  "reason": "-"
}
```

Secret values are never logged. Only key names and the command that was run.

---

## Security Notes

- **No disk writes**: Secrets go from OS keychain directly into the child process memory — nothing is ever written to a file, `.env`, or any other location
- **No parent access**: The `agentsecrets` process passes secrets to the child at spawn time via the OS `execve`-style interface — the secrets exist in the child's address space, not the parent's
- **Process-scoped lifetime**: When the child exits (or is killed), the environment variables are gone with it
- **Signal forwarding**: `SIGINT` and `SIGTERM` are forwarded to the child so the process can handle them gracefully (e.g., Django's runserver cleanup)
- **Conflicts**: If a secret key name already exists in the parent environment (e.g., from a previous export), the keychain value takes precedence

---

## Prerequisites

- Active project: `agentsecrets project use <name>`
- Secrets provisioned: `agentsecrets secrets pull` or `agentsecrets secrets set KEY=value`
- Verify with: `agentsecrets secrets list`
