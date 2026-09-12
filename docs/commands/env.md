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
4. Spawns the child via `exec.Command`. `stdout` and `stderr` pass through a redactor that replaces secret values with `[REDACTED]`; `stdin` is passed straight through
5. Makes the child non-dumpable, so no other process running as the same user can read its environment, and (when the platform supports it) loads a small guard that does the same from inside the child and blocks it from reading the parent's memory
6. With `--sandbox`, runs the child with no network egress
7. Forwards `SIGINT` and `SIGTERM` to the child process (so `Ctrl+C` works exactly as expected)
8. Exits with the child's exact exit code

The parent writes no secret to disk. It holds the values only to build the child's environment and the redaction set, and does not retain them after spawning. While the child runs, its secrets live in the child's environment; when the child exits they are gone.

**What the guard does and does not do.** The child is protected against *other* processes reading its environment, and its output is redacted. Redaction is best-effort hygiene, not a security boundary: a child that deliberately splits or encodes a value can defeat it, and a statically linked child cannot load the guard at all (you are told when that happens). To stop a value leaving the machine, use `--sandbox` (no network egress).

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

Secret values are never logged. The audit record holds the key names, the child's resolved path and SHA-256, its PID, its exit code, and the hosts its credentials name (see below).

---

## Security Notes

- **No disk writes by the parent**: Secrets go from the OS keychain into the child's environment; the parent writes nothing to a file, `.env`, or anywhere else. Containment of the *child's* disk writes is not enforced (use `--sandbox` for a no-egress run).
- **Not readable by other processes**: The child is made non-dumpable, so another process running as the same user cannot read its environment via `/proc/<pid>/environ` or its memory via `/proc/<pid>/mem`. The parent is made non-dumpable too, so the child cannot read the parent's memory.
- **Output is redacted, best-effort**: Secret values in the child's `stdout`/`stderr` are replaced with `[REDACTED]`. This is hygiene, not a guarantee: a child that controls its own output can interleave or encode a value to evade it, and C stdio output is not covered. Do not rely on it as a boundary.
- **Static binaries**: A statically linked child cannot load the guard; `env` tells you when this is the case. Such a child is not protected by the per-process or redaction layers.
- **`--sandbox`**: Runs the child with no network egress (Linux). This is what prevents an exfiltrated value from being sent anywhere.
- **Process-scoped lifetime**: When the child exits (or is killed), the environment variables are gone with it
- **Signal forwarding**: `SIGINT` and `SIGTERM` are forwarded to the child so the process can handle them gracefully (e.g., Django's runserver cleanup)
- **Conflicts**: If a secret key name already exists in the parent environment (e.g., from a previous export), the keychain value takes precedence
- **Host hints**: When a credential names a host (a `DATABASE_URL`, an API base URL) that is not in the workspace allowlist, `env` prints the host and the `agentsecrets allowlist add` command to route that traffic through AgentSecrets. It never enforces this — the command runs either way.

---

## Prerequisites

- Active project: `agentsecrets project use <name>`
- Secrets provisioned: `agentsecrets secrets pull` or `agentsecrets secrets set KEY=value`
- Verify with: `agentsecrets secrets list`
