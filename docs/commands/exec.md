# agentsecrets exec

> Inject decrypted secrets directly into child process memory without creating unencrypted `.env` files.

## Usage

```bash
agentsecrets exec -- <command> [args...]
```

The `--` separator is required. Everything following `--` is executed with secrets resolved in process address space.

---

## Examples

```bash
# Node.js
agentsecrets exec -- npm run dev

# Python
agentsecrets exec -- python manage.py runserver

# Go
agentsecrets exec -- go run ./cmd/server
```

For full details and comparison with proxy injection, visit:
👉 **[Process Execution (exec) Guide](https://docs.agentsecrets.tech/env-injection/exec)**
👉 **[Environment Injection Overview](https://docs.agentsecrets.tech/env-injection/overview)**