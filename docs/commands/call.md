# agentsecrets call

> Make a single authenticated API call without exposing credentials.

## Usage

```bash
agentsecrets call --url <URL> [options]
```

## Description

`agentsecrets call` is a one-shot proxy command. It resolves the specified secret from the OS keychain, injects it into the outbound HTTP request at the transport layer, makes the request, and returns the API response — without the secret value ever appearing in your terminal, in a log, or in agent context.

It's the equivalent of `curl` with credential injection handled by the keychain rather than the shell.

---

## Options

| Flag | Description |
|---|---|
| `--url` | **Required.** Target API URL |
| `--method` | HTTP method (default: `GET`) |
| `--body` | Request body (string, typically JSON) |
| `--bearer KEY` | Inject secret as `Authorization: Bearer <value>` |
| `--basic KEY` | Inject secret as `Authorization: Basic base64(<value>)` — format: `user:pass` |
| `--header X-Name=KEY` | Inject secret as custom header `X-Name: <value>` |
| `--query param=KEY` | Inject secret as URL query param `?param=<value>` |
| `--body-field path=KEY` | Set secret at JSON body path (dot notation for nesting) |
| `--form-field field=KEY` | Set secret in form-encoded body |

Multiple injection flags can be combined in a single call.

---

## Examples

### Bearer token (most common)

```bash
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY
agentsecrets call --url https://api.openai.com/v1/models --bearer OPENAI_KEY
```

### POST with body

```bash
agentsecrets call \
  --url https://api.stripe.com/v1/charges \
  --method POST \
  --bearer STRIPE_KEY \
  --body '{"amount": 1000, "currency": "usd", "source": "tok_visa"}'
```

### Custom header (API key in header)

```bash
agentsecrets call \
  --url https://api.sendgrid.com/v3/mail/send \
  --method POST \
  --header X-Api-Key=SENDGRID_KEY \
  --body '{"personalizations":[...]}'
```

### Query parameter

```bash
agentsecrets call \
  --url "https://maps.googleapis.com/maps/api/geocode/json?address=Lagos" \
  --query key=GOOGLE_MAPS_KEY
```

### Basic auth

```bash
# JIRA_CREDS stored in keychain as "user@email.com:api_token"
agentsecrets call \
  --url https://yourcompany.atlassian.net/rest/api/2/issue/PROJ-123 \
  --basic JIRA_CREDS
```

### JSON body injection

```bash
# Inject secret into JSON body at a specific path
agentsecrets call \
  --url https://api.example.com/oauth/token \
  --method POST \
  --body '{"grant_type": "client_credentials"}' \
  --body-field client_secret=CLIENT_SECRET
```

`--body-field client_secret=CLIENT_SECRET` sets `body.client_secret` to the value of `CLIENT_SECRET` from the keychain. Use dots for nesting: `--body-field config.auth.token=TOKEN` sets `body.config.auth.token`.

### Multiple credentials

```bash
agentsecrets call \
  --url https://api.example.com/data \
  --bearer AUTH_TOKEN \
  --header X-Org-Id=ORG_SECRET
```

### Form-encoded body

```bash
agentsecrets call \
  --url https://oauth.example.com/token \
  --method POST \
  --form-field api_key=API_KEY \
  --form-field client_id=CLIENT_ID
```

---

## How It Works

1. Parses injection flags to build an injection spec: `{bearer: "STRIPE_KEY", header_X-Org-Id: "ORG_SECRET"}`
2. For each key name in the spec, resolves the value from the OS keychain
3. Applies injections to the request at transport layer:
   - Bearer → sets `Authorization: Bearer <value>`
   - Header → sets the named header
   - Query → appends `?param=<value>` to the URL
   - Body → unmarshals body, sets field, re-marshals
4. Makes the outbound HTTP request
5. If the response body contains any injected value, replaces with `[REDACTED_BY_AGENTSECRETS]`
6. Prints response status and body
7. Writes audit log entry

The secret value is in memory only for the duration of the request. It is never printed, never logged, never returned.

---

## vs. `agentsecrets env`

| | `agentsecrets call` | `agentsecrets env` |
|---|---|---|
| **Best for** | One-shot API calls | Long-running processes, dev servers |
| **Injection method** | HTTP transport layer | OS environment variables |
| **Audit** | Per-request entry | Per-invocation entry |
| **Use when** | You need to hit an endpoint right now | You're starting a server/CLI that needs env vars |

---

## Audit Log

Every `call` writes to `~/.agentsecrets/proxy.log`:

```json
{
  "timestamp": "2026-03-03T14:23:01Z",
  "method": "POST",
  "target_url": "https://api.stripe.com/v1/charges",
  "secret_keys": ["STRIPE_KEY"],
  "auth_styles": ["bearer"],
  "status_code": 200,
  "status": "OK",
  "reason": "-",
  "redacted": false,
  "duration_ms": 312
}
```

If the domain is not in the workspace allowlist, the call is blocked and logged:

```json
{
  "status": "BLOCKED",
  "reason": "not_allowed",
  "status_code": 403
}
```
