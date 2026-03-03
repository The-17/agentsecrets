# Proxy Engine & MCP Server

> Let your AI agents make authenticated API calls without ever seeing your credentials.

AgentSecrets provides two interfaces for AI agents to securely interact with APIs:

| Interface | Transport | Best For |
|-----------|-----------|----------|
| **MCP Server** | stdio (in-process) | Claude Desktop, Cursor, Windsurf |
| **HTTP Proxy** | localhost:8765 | Custom agents, scripts, any HTTP client |

Both paths share the same core engine that resolves secrets from your OS keychain, injects them into outbound requests, and logs every call.

---

## MCP Server (Recommended)

### Setup for Claude Desktop

1. Build AgentSecrets:
   ```bash
   go build -o agentsecrets ./cmd/agentsecrets
   ```

2. Add to your Claude Desktop config:

   **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
   **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

   ```json
   {
     "mcpServers": {
       "agentsecrets": {
         "command": "/path/to/agentsecrets",
         "args": ["mcp", "serve"]
       }
     }
   }
   ```

3. Restart Claude Desktop. You'll see two new tools: `api_call` and `list_secrets`.

### Available Tools

#### `list_secrets`

Discover what secret keys are available. Returns **key names only**, never values.

**Example prompt:**
> "What API keys do I have in this project?"

**Claude's response:**
```
Found 3 secret(s):

  • STRIPE_KEY
  • OPENAI_API_KEY
  • GITHUB_TOKEN

Use these key names in api_call's injections parameter.
```

#### `api_call`

Make an authenticated API call. The AI sends key *names*, the engine resolves actual values from the keychain.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `url` | string | ✅ | Target API URL |
| `method` | string | | HTTP method (default: GET) |
| `body` | string | | Request body (JSON string) |
| `headers` | object | | Extra request headers |
| `injections` | object | ✅ | Map of injection spec → secret key name |

**Injection specs:**

| Spec | Effect |
|------|--------|
| `"bearer": "KEY"` | `Authorization: Bearer <value>` |
| `"basic": "KEY"` | `Authorization: Basic base64(<value>)` |
| `"header:X-Name": "KEY"` | `X-Name: <value>` |
| `"query:param": "KEY"` | `?param=<value>` |
| `"body:json.path": "KEY"` | Sets value at JSON body path |
| `"form:field": "KEY"` | Sets form field value |

**Example prompt:**
> "Create a Stripe test charge for $10"

Claude calls:
```json
{
  "url": "https://api.stripe.com/v1/charges",
  "method": "POST",
  "body": "{\"amount\": 1000, \"currency\": \"usd\", \"source\": \"tok_visa\"}",
  "injections": {"bearer": "STRIPE_KEY"}
}
```

**Claude sees:**
```
HTTP 200

{"id": "ch_3Pk...", "amount": 1000, "currency": "usd", ...}
```

**Claude never sees:** `sk_test_51H...` (the actual Stripe key).

---

## HTTP Proxy Server

For non-MCP agents or scripts that speak HTTP.

### Start

```bash
agentsecrets proxy start              # Default port 8765
agentsecrets proxy start --port 9000  # Custom port
```

### Make Requests

Send requests to `http://localhost:8765/proxy` with `X-AS-*` headers:

```bash
# Bearer token injection
curl http://localhost:8765/proxy \
  -H "X-AS-Target-URL: https://api.stripe.com/v1/charges" \
  -H "X-AS-Method: POST" \
  -H "X-AS-Inject-Bearer: STRIPE_KEY" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "amount=1000&currency=usd&source=tok_visa"

# Custom header injection
curl http://localhost:8765/proxy \
  -H "X-AS-Target-URL: https://api.openai.com/v1/chat/completions" \
  -H "X-AS-Inject-Bearer: OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}'

# Query parameter injection
curl http://localhost:8765/proxy \
  -H "X-AS-Target-URL: https://maps.googleapis.com/maps/api/geocode/json?address=NYC" \
  -H "X-AS-Inject-Query-key: GOOGLE_MAPS_KEY"

# Multiple injections
curl http://localhost:8765/proxy \
  -H "X-AS-Target-URL: https://api.example.com/data" \
  -H "X-AS-Inject-Bearer: AUTH_TOKEN" \
  -H "X-AS-Inject-Header-X-Org-ID: ORG_SECRET"
```

### Header Reference

| Header | Required | Description |
|--------|----------|-------------|
| `X-AS-Target-URL` | ✅ | Upstream API URL |
| `X-AS-Method` | | HTTP method (defaults to request method) |
| `X-AS-Agent-ID` | | Agent identifier for audit logging |
| `X-AS-Inject-Bearer` | | Bearer token injection |
| `X-AS-Inject-Basic` | | Basic auth injection (secret format: `user:pass`) |
| `X-AS-Inject-Header-<Name>` | | Custom header injection |
| `X-AS-Inject-Query-<Param>` | | Query parameter injection |
| `X-AS-Inject-Body-<Path>` | | JSON body injection (dashes → dots) |
| `X-AS-Inject-Form-<Key>` | | Form body injection |

### Health Check

```bash
curl http://localhost:8765/health
# {"project":"your-project-id","status":"ok"}
```

---

## Audit Log

Every proxied call is logged to `~/.agentsecrets/proxy.log` in JSONL format.

**What's logged:** Timestamp, secret key names, agent ID, method, URL, auth styles, status code, duration.
**What's NEVER logged:** Secret values.

### View Logs

```bash
agentsecrets proxy logs                    # All entries
agentsecrets proxy logs --last 5           # Last 5 entries
agentsecrets proxy logs --secret STRIPE_KEY # Filter by key
```

### Log Format

```json
{
  "timestamp": "2026-02-25T10:00:00Z",
  "secret_keys": ["STRIPE_KEY"],
  "agent_id": "mcp",
  "method": "POST",
  "target_url": "https://api.stripe.com/v1/charges",
  "auth_styles": ["bearer"],
  "status_code": 200,
  "status": "OK",
  "reason": "-",
  "redacted": false,
  "duration_ms": 245
}
```

When a response body contains an echoed credential, the log shows:

```json
{
  "status": "OK",
  "reason": "credential_echo",
  "redacted": true
}
```

---

## Response Body Redaction

If an external API echoes back the injected credential in its response body, the proxy automatically replaces the value with `[REDACTED_BY_AGENTSECRETS]` before the response reaches the agent.

This prevents **credential echo exfiltration** — a class of attack where a malicious API is designed to reflect secrets back into agent context.

- The `Content-Length` header is recalculated after redaction
- The audit log records `redacted: true` and `reason: "credential_echo"`
- The CLI shows `(REDACTED)` in the proxy logs table

---

## Environment Variable Injection

For tools that require secrets as environment variables (Stripe CLI, SDKs, dev servers):

```bash
agentsecrets env -- stripe mcp
agentsecrets env -- node server.js
agentsecrets env -- npm run dev
```

- Values are injected from the OS keychain into the child process environment
- Nothing is written to disk
- Secrets exist only in the child process memory during its lifetime
- Signal forwarding (SIGINT/SIGTERM) and exit code passthrough are handled
- Key names (never values) are logged to the audit log with method `ENV`

---

## Security

- **Zero-Trust Workspace Allowlist**: The proxy enforces a deny-by-default domain allowlist synced from your workspace. Unauthorized domains are blocked with 403 Forbidden. Add domains via `agentsecrets workspace allowlist add <domain> [domain...]`. Allowlist modifications require admin role and password.
- **Response Body Redaction**: If an API echoes back the injected credential, the proxy replaces it with `[REDACTED_BY_AGENTSECRETS]` before the response reaches the agent. Logged as `credential_echo`.
- Secret values are **resolved at execution time** from the OS keychain — they exist in memory only during the request
- The AI agent **never receives** secret values in any response
- The audit log records **key names and metadata**, never values
- The HTTP proxy binds to **localhost only** — not accessible from the network
- All communication with the MCP server is over **stdio** — no network exposure
