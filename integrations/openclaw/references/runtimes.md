# Runtimes — local and cloud

One promise, two runtimes. Mode changes where a value is resolved, never what
the agent may see.

## Which one am I in

```bash
agentsecrets mode
```

Precedence, highest first: `--cloud/--local` flag on one call,
`AGENTSECRETS_MCP_MODE`, `AGENTSECRETS_USE_CLOUD=1`, saved
mode (`agentsecrets mode cloud` or `agentsecrets mode local`), workload token
(`AGENTSECRETS_TOKEN` or `AGENTSECRETS_TOKEN_FILE`), then the
local default.

## Local

- Resolution: OS keychain via the local proxy on loopback.
- Enforcement in-process: allowlist, policy, SSRF pinning, redaction, audit.
- Offline. No entitlement needed.
- Redaction marker: `[REDACTED_BY_AGENTSECRETS]`.
- Injection styles: bearer, basic, header, query, body, form.

## Cloud

- Resolution: the cloud resolver substitutes `{{KEY}}` handles
  server-side; the value never crosses your process boundary.
- Enforcement at the resolver: allowlist and policy are evaluated there; the
  local proxy still audits.
- Needs a workload token and a billed entitlement (402 when exhausted).
- Redaction marker: `[REDACTED]`.
- Injection styles: header and body only. If a call needs basic/query/form,
  run that call with `--local` or move the value into a header. Do
  not try to work around it.

## What both guarantee

- The agent never sees a value.
- Audit rows record identifiers and chain hashes, never values.
- A redaction marker in output means an echo was caught and scrubbed. That is
  the system working, not an error.

## Failure meanings differ

The same symptom means different things per runtime, which is why you say
which runtime you are in when you report a failure:

- 403 with the domain named: allowlist refusal (both runtimes).
- 402: entitlement exhausted (cloud only).
- Connection refused on loopback: local proxy not running (local only).
- 401 on resolve: workload token expired or revoked (cloud only).
