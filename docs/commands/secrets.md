# agentsecrets secrets

> Manage secrets for the active project — store, sync, and inspect credentials.

## Subcommands

```
agentsecrets secrets list
agentsecrets secrets set <KEY=value> [KEY=value...]
agentsecrets secrets delete <KEY>
agentsecrets secrets pull [--force]
agentsecrets secrets push
agentsecrets secrets diff
```

---

## agentsecrets secrets list

List all secret key names for the active project.

```bash
agentsecrets secrets list
agentsecrets secrets list --project my-other-app
```

Returns **key names only** — values are never decrypted or displayed. The list is fetched from the API and compared against what's in the local keychain.

```
STRIPE_KEY
OPENAI_KEY
DATABASE_URL
SENDGRID_KEY
```

---

## agentsecrets secrets set

Store or update a secret. The value is encrypted client-side before being sent to the server.

```bash
agentsecrets secrets set STRIPE_KEY=sk_live_51H... DATABASE_URL=postgresql://user:pass@host:5432/db
```

**What happens:**
1. Retrieves the workspace key from `~/.agentsecrets/config.json`
2. Encrypts the value with AES-256-GCM: `ciphertext = AES-GCM(workspace_key, nonce, value)`
3. Sends `{key, ciphertext+nonce}` to the API — server stores the blob
4. If StorageMode is Keychain, also writes the value to the OS keychain

The API only ever receives and stores the ciphertext. It cannot decrypt.

### Naming Conventions

Use `UPPER_SNAKE_CASE`. Common patterns:

```bash
# API keys
STRIPE_KEY
OPENAI_KEY
GITHUB_TOKEN
SENDGRID_KEY

# Database
DATABASE_URL
REDIS_URL

# Application
DJANGO_SECRET_KEY
JWT_SECRET
SESSION_SECRET

# Service accounts
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
GCP_SERVICE_ACCOUNT_JSON
```

---

## agentsecrets secrets push

Encrypt all secrets from the current source (keychain or `.env` file) and upload them to the project.

```bash
agentsecrets secrets push
```

**StorageMode 1 (Keychain):** Reads all keys from the OS keychain and pushes them.  
**StorageMode 0 (Standard):** Reads your `.env` file and pushes all entries.

Useful when:
- Onboarding a new project (push your existing `.env` once, then delete it)
- Syncing changes made directly to the `.env` or keychain

---

## agentsecrets secrets pull

Download secrets from the project and write them locally.

```bash
agentsecrets secrets pull
agentsecrets secrets pull --force   # overwrite without conflict prompts
```

**What happens:**
1. Fetches encrypted blobs from the API
2. Decrypts each with the workspace key (AES-256-GCM)
3. Writes values to:
   - **StorageMode 1**: OS keychain, keyed by `projectID/KEY_NAME`
   - **StorageMode 2**: Local `.env` file

**Conflict handling:** If a key already exists locally with a different value, the CLI shows a diff and prompts before overwriting. Use `--force` to skip confirmation.

Pull is safe to run repeatedly, it's idempotent.

---

## agentsecrets secrets diff

Compare local secrets (keychain or `.env`) with what's stored in the cloud.

```bash
agentsecrets secrets diff
```

Shows three categories:
- **Only local** — exists on your machine, not pushed yet
- **Only remote** — in the cloud, not pulled yet
- **Differs** — key exists in both, but values differ

Useful before deployments, before pushing, or to debug sync issues. Values are never shown — only key names and their sync status.

Example output:
```
Only local:   NEW_KEY
Only remote:  DEPRECATED_KEY
Differs:      DATABASE_URL
```

---

## agentsecrets secrets delete

Remove a secret from the project.

```bash
agentsecrets secrets delete STRIPE_KEY
```

Deletes the key from:
- The remote API
- The local keychain (if StorageMode 1)
- The local `.env` file (if StorageMode 0)

Prompts for confirmation before deleting.

---

## Storage Modes

| Mode | Where `pull` writes | Where `push` reads from |
|---|---|---|
| `1` — Keychain | OS keychain | OS keychain |
| `2` — Standard | `.env` file (plaintext) | `.env` file |

The storage mode is set during `agentsecrets init` and stored in `.agentsecrets/project.json`. You can check it with `agentsecrets status`.
