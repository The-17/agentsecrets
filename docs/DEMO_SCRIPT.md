# Demo Script — AgentSecrets Proxy Engine

> This script documents the exact demo flow for showcasing how AI agents make authenticated API calls without seeing credentials.

---

## Prerequisites

1. **AgentSecrets installed and configured:**
   ```bash
   agentsecrets login
   agentsecrets project use demo-project
   ```

2. **Stripe test key stored:**
   ```bash
   agentsecrets secrets set STRIPE_KEY            # prompts, so the value never enters the command
   ```

3. **Verify secrets are stored:**
   ```bash
   agentsecrets secrets list
   # Should show: STRIPE_KEY
   ```

---

## Demo A — MCP Server with Claude

### Setup

1. Build the binary:
   ```bash
   cd /home/theapiartist/work/agentsecrets
   go build -o agentsecrets ./cmd/agentsecrets
   ```

2. Add to Claude Desktop config:
   ```json
   {
     "mcpServers": {
       "agentsecrets": {
         "command": "/home/theapiartist/work/agentsecrets/agentsecrets",
         "args": ["mcp", "serve"]
       }
     }
   }
   ```

3. Restart Claude Desktop.

### Script

**Step 1 — Discovery**

Ask Claude:
> "What secret keys do I have available?"

Claude calls `list_secrets` → sees key names: `STRIPE_KEY`

**Step 2 — Make the call**

Ask Claude:
> "Create a $20.00 test charge on Stripe using my STRIPE_KEY."

Claude calls:
```json
{
  "name": "api_call",
  "arguments": {
    "url": "https://api.stripe.com/v1/charges",
    "method": "POST",
    "body": "{\"amount\": 2000, \"currency\": \"usd\", \"source\": \"tok_visa\"}",
    "injections": {"bearer": "STRIPE_KEY"}
  }
}
```

Claude sees the response (`HTTP 200`, charge ID, etc.) — **never the key**.

**Step 3 — Show the audit log**

```bash
agentsecrets proxy logs --last 1
```

Output:
```json
{
  "timestamp": "2026-02-25T...",
  "secret_keys": ["STRIPE_KEY"],
  "agent_id": "mcp",
  "method": "POST",
  "target_url": "https://api.stripe.com/v1/charges",
  "auth_styles": ["bearer"],
  "status_code": 200,
  "duration_ms": 312
}
```

**Key talking point:** The log shows *what key was used* and *what API was hit*, but never the key value itself.

---

## Demo B — HTTP Proxy with curl

### Setup

```bash
# Terminal 1: Start the proxy
agentsecrets proxy start

# Terminal 2: Verify health
curl http://localhost:8765/health
```

### Script

**Step 1 — Bearer token injection**

```bash
curl -s http://localhost:8765/proxy \
  -H "X-AS-Target-URL: https://api.stripe.com/v1/balance" \
  -H "X-AS-Inject-Bearer: STRIPE_KEY" | jq .
```

Expected: Stripe balance response with `available` and `pending` amounts.

**Step 2 — POST with body**

```bash
curl -s http://localhost:8765/proxy \
  -X POST \
  -H "X-AS-Target-URL: https://api.stripe.com/v1/charges" \
  -H "X-AS-Method: POST" \
  -H "X-AS-Inject-Bearer: STRIPE_KEY" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "amount=1000&currency=usd&source=tok_visa" | jq .
```

Expected: Charge created, ID returned.

**Step 3 — Audit trail**

```bash
agentsecrets proxy logs --last 2
```

Shows both calls logged with key names, never values.

---

## Key Points to Highlight

1. **Zero credential exposure** — The agent asks "use STRIPE_KEY" and never sees `sk_test_...`
2. **Full audit trail** — Every call logged with key names, never values
3. **Works with any API** — Stripe, OpenAI, Google Maps, custom APIs
4. **6 injection styles** — Bearer, basic, header, query, body, form
5. **Two interfaces** — MCP (for Claude/Cursor) and HTTP proxy (for anything)
