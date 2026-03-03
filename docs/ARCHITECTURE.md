# Architecture

> How AgentSecrets works under the hood: the encryption model, the proxy engine, and the zero-trust enforcement layer.

---

## The Core Guarantee

AgentSecrets makes two structural guarantees:

1. **The server cannot decrypt your secrets** — the server only stores encrypted blobs. Even with full database access, decryption is impossible without your private key, which never leaves your device.

2. **AI agents cannot read your secrets** — at no point during any operation does a secret value travel into agent context. Agents see key names, endpoints, and API responses. Never values.

These aren't policy decisions, they're enforced by the architecture.

---

## Encryption Model

### Key Hierarchy

```
Password
  └─(Argon2id)─→ Password-Derived Key
                    └─(AES-256-GCM decrypt)─→ Private Key (X25519)
                                                └─(NaCl SealedBox decrypt)─→ Workspace Key
                                                                               └─(AES-256-GCM)─→ Secrets
```

Three layers, each with a specific role:

| Layer | Algorithm | Purpose |
|---|---|---|
| Password → Key | Argon2id | Memory-hard key derivation — expensive to brute-force |
| Private Key | X25519 | Asymmetric keypair — enables team sharing without server involvement |
| Workspace Key | AES-256-GCM | AEAD symmetric encryption for actual secret values |

### Key Storage

| Key | Where Stored | Who Can Access |
|---|---|---|
| Private Key | OS keychain (encrypted by OS + password-derived key) | You only |
| Workspace Key | `~/.agentsecrets/config.json` (decrypted at login) | You + team members (each with their own encrypted copy) |
| Password-Derived Key | Never stored — derived on demand | You only (requires password) |

The OS keychain itself is protected by the operating system:
- **macOS**: Keychain Access — protected by login password + Secure Enclave on Apple Silicon
- **Windows**: Windows Credential Manager — protected by Windows login and DPAPI
- **Linux**: Secret Service (GNOME Keyring / KWallet) — protected by user session

### How Secrets Are Encrypted

When you run `agentsecrets secrets set API_KEY=sk_live_...`:

1. The CLI retrieves the workspace key from `~/.agentsecrets/config.json`
2. Generates a random 12-byte nonce
3. Encrypts the value with AES-256-GCM: `ciphertext = AES-GCM(workspace_key, nonce, plaintext)`
4. Sends `{key: "API_KEY", value: base64(nonce + ciphertext)}` to the API
5. The API stores the encrypted blob. It has no access to the workspace key, so it cannot decrypt

When you run `agentsecrets secrets pull`:

1. The CLI fetches all encrypted blobs for the project
2. For each blob: splits ciphertext and nonce, decrypts with workspace key
3. Writes plaintext values to OS keychain (StorageMode 1) or `.env` file (StorageMode 0)

The server at no point sees a plaintext value.

### Team Sharing

When you invite someone to a workspace:

1. Their public key (X25519) is fetched from the server
2. The workspace key is encrypted with their public key using NaCl SealedBox
3. This encrypted copy is sent to the server to be stored for them
4. When they log in, they download and decrypt their copy using their private key

The server stores one encrypted copy of the workspace key per user. It cannot combine them or derive the plaintext workspace key,  only the user's private key (which never leaves their device) can decrypt it.

---

## Proxy Architecture

The proxy is the layer that allows AI agents to make authenticated API calls without ever receiving credential values.

### How a Proxied Request Works

```
Agent (Claude / bot / script)
  │
  │  POST http://localhost:8765/proxy
  │  X-AS-Target-URL: https://api.stripe.com/v1/charges
  │  X-AS-Inject-Bearer: STRIPE_KEY          ← key name, not value
  │
  ▼
AgentSecrets Proxy (localhost:8765)
  1. Validates session token
  2. Checks domain against workspace allowlist  ← zero-trust enforcement
  3. Looks up "STRIPE_KEY" in OS keychain       ← resolves value from keychain
  4. Builds outbound request:
     Authorization: Bearer sk_live_51H...      ← actual value injected here
  5. Forwards to api.stripe.com/v1/charges
  6. Receives response
  7. Scans response body for echoed credential  ← redaction layer
  8. Returns response to agent                  ← agent never saw the value
  │
  ▼
Agent sees: HTTP 200 + response body (scrubbed if credential was echoed)
Agent never sees: sk_live_51H...
```

The proxy listens on `localhost:8765` — it is not accessible from the network, only from processes on the same machine.

### Zero-Trust Domain Allowlist

Every outbound proxy request is checked against a workspace-level domain allowlist **before** the secret is resolved from the keychain. This is the enforcement order deliberately, secrets are never even accessed if the domain isn't authorized.

```
Incoming proxy request
  │
  ├─ Extract target domain from X-AS-Target-URL
  ├─ Check domain against workspace allowlist
  │
  ├─ NOT ALLOWED → return 403, log "not_allowed", stop
  │
  └─ ALLOWED → resolve secret from keychain, inject, forward
```

The allowlist is workspace-level (shared across all team members) and can only be modified by workspace admins. Modifications require password verification, the admin must be present and authenticated.

```bash
agentsecrets workspace allowlist add api.stripe.com api.openai.com
agentsecrets workspace allowlist list
agentsecrets workspace allowlist log    # view blocked attempts
```

This prevents:
- **Prompt injection attacks** — a compromised prompt cannot redirect a secret to an exfiltration endpoint
- **SSRF** — agents cannot proxy requests to internal network endpoints unless explicitly allowed
- **Exfiltration via DNS** — subdomains must match (e.g., `api.stripe.com` does not automatically allow `evil.api.stripe.com`)

### Response Body Redaction

Some APIs echo back authentication headers in their response body (a common pattern in debugging APIs, or in adversarial scenarios). If the proxy detects the injected secret value anywhere in the response body, it replaces every occurrence with `[REDACTED_BY_AGENTSECRETS]` before returning the response.

```
Response from api.example.com:
{"authenticated": true, "token": "sk_live_51H..."}
                                   ↑ matched as echoed credential

After redaction:
{"authenticated": true, "token": "[REDACTED_BY_AGENTSECRETS]"}

Audit log:
{"reason": "credential_echo", "redacted": true}
```

The `Content-Length` header is recalculated after substitution. From the agent's perspective, the credential was never in the response.

### Authentication Styles

The proxy supports 6 injection styles via `X-AS-Inject-*` headers:

| Header | Resolves To |
|---|---|
| `X-AS-Inject-Bearer: KEY` | `Authorization: Bearer <value>` |
| `X-AS-Inject-Basic: KEY` | `Authorization: Basic base64(<value>)` (format: `user:pass`) |
| `X-AS-Inject-Header-X-Name: KEY` | `X-Name: <value>` |
| `X-AS-Inject-Query-param: KEY` | `?param=<value>` appended to URL |
| `X-AS-Inject-Body-json.path: KEY` | Value set at JSON body path (dots = nesting) |
| `X-AS-Inject-Form-field: KEY` | Value set in form-encoded body |

Multiple injection headers can be combined in a single request.

### MCP Interface

The MCP server wraps the same proxy engine behind the Model Context Protocol, exposing two tools:

- `list_secrets` — returns key names for the active project (never values)
- `api_call` — takes URL, method, body, headers, and an injections map (`{"bearer": "STRIPE_KEY"}`) — routes through the same proxy engine

Communication is over stdio, not HTTP — no network port is opened.

---

## Environment Injection (`agentsecrets env`)

`agentsecrets env` is a process wrapper that reads secrets from the OS keychain and passes them directly to the child process's environment at spawn time. The parent process (`agentsecrets`) never uses the values — it passes them to the OS's process creation API which sets them in the child's address space.

```
agentsecrets env -- python manage.py runserver
  │
  ├─ Load active project from .agentsecrets/project.json
  ├─ keyring.GetAllProjectSecrets(projectID) → [{key: "DB_PASSWORD", value: "..."}, ...]
  ├─ Build env: os.Environ() + project secrets (project overrides on conflict)
  ├─ exec.Command("python", "manage.py", "runserver").Env = builtEnv
  ├─ Wire stdin/stdout/stderr through
  ├─ Forward SIGINT/SIGTERM to child
  ├─ Write audit log: method=ENV, secret_keys=[...], target="python manage.py runserver"
  └─ Exit with child's exit code
```

The child process reads `os.environ["DB_PASSWORD"]` (Python) or `process.env.DB_PASSWORD` (Node.js) normally — it has no knowledge that the values came from a keychain.

---

## Audit Logging

Every proxied call (proxy, MCP, `agentsecrets call`, or `agentsecrets env`) is logged to `~/.agentsecrets/proxy.log` in JSON Lines format.

### Log Entry Schema

```go
type AuditEvent struct {
    Timestamp  time.Time `json:"timestamp"`
    SecretKeys []string  `json:"secret_keys"`   // key names only
    AgentID    string    `json:"agent_id"`
    Method     string    `json:"method"`         // GET, POST, ENV, etc.
    TargetURL  string    `json:"target_url"`
    AuthStyles []string  `json:"auth_styles"`
    StatusCode int       `json:"status_code"`
    Status     string    `json:"status"`         // "OK", "BLOCKED"
    Reason     string    `json:"reason"`         // "-", "credential_echo", "not_allowed"
    Redacted   bool      `json:"redacted"`
    DurationMs int64     `json:"duration_ms"`
}
```

There is no `Value` field. This is intentional, the struct itself cannot carry credential values.

---

## Config Files

### Global config — `~/.agentsecrets/config.json`

```json
{
  "api_endpoint": "https://api.agentsecrets.com",
  "user_email": "you@example.com",
  "current_workspace_id": "ws_abc123",
  "workspaces": {
    "ws_abc123": {
      "name": "My Workspace",
      "workspace_key": "<encrypted workspace key>",
      "allowlist": ["api.stripe.com", "api.openai.com"]
    }
  },
  "token": "<JWT access token>"
}
```

The workspace key stored here is the **decrypted** workspace key, it was decrypted at login using your private key (from the OS keychain) and is cached here for performance. This file should be protected by OS file permissions (read only by your user).

### Project config — `.agentsecrets/project.json`

```json
{
  "project_id": "proj_xyz789",
  "project_name": "my-app",
  "workspace_id": "ws_abc123",
  "storage_mode": 1,
  "last_pull": "2026-03-03T22:00:00Z",
  "last_push": "2026-03-03T21:00:00Z"
}
```

This file lives in the project directory (alongside your code). It links the directory to the remote project and is safe to commit, it contains no credentials.

---

## Package Overview

| Package | Responsibility |
|---|---|
| `cmd/agentsecrets/commands/` | CLI command implementations (Cobra) |
| `pkg/api/` | HTTP API client with dot-notation endpoint routing |
| `pkg/auth/` | JWT management + automatic token refresh middleware |
| `pkg/config/` | Global and project config load/save/validation |
| `pkg/crypto/` | All encryption/decryption: X25519, AES-256-GCM, Argon2id |
| `pkg/keyring/` | OS keychain read/write for secrets and auth tokens |
| `pkg/mcp/` | MCP server implementation (tools: api_call, list_secrets) |
| `pkg/projects/` | Project API wrappers |
| `pkg/proxy/` | HTTP proxy engine, injector, allowlist enforcement, redaction, audit |
| `pkg/secrets/` | Secret management, dotenv parsing, diff computation |
| `pkg/ui/` | Terminal UI components (spinner, table, prompts) |
| `pkg/workspaces/` | Workspace API wrappers + allowlist management |

---

## Security Properties

| Property | How It's Enforced |
|---|---|
| Server can't decrypt secrets | Secrets encrypted client-side with workspace key; server only stores ciphertext |
| Agent can't read secret values | No code path puts a value into agent context; proxy resolves at injection time |
| Prompt injection can't exfiltrate | Domain allowlist enforced before secret is resolved from keychain |
| API echoed credential is scrubbed | Response body scanned post-response, before returning to agent |
| Team member can't modify allowlist | Admin role required + password verification for allowlist writes |
| Audit log can't contain values | `AuditEvent` struct has no value field |
| Proxy not exposed to network | Binds to `127.0.0.1` only |
| MCP not exposed to network | Uses stdio transport, no TCP port |