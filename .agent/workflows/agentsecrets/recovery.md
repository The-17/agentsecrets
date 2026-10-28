# Recovery — failure modes and hand-offs

Say which runtime you are in first (see runtimes.md). Then find the symptom.

## Allowlist 403

Symptom: the call is refused and the response names the domain.

Do not retry another host, do not bypass the proxy, do not try to edit the
allowlist. Tell the human which domain and why, then give them:

```bash
agentsecrets workspace allowlist add <domain>
```

Wait for their confirmation, then retry once.

## Wrong runtime

Symptom: cloud verbs fail offline, or local calls fail with no keychain
session.

```bash
agentsecrets mode
agentsecrets doctor --check-only
```

Report what mode reports and where it came from. Switching the saved mode is
the human's call: `agentsecrets mode cloud` or `agentsecrets mode local`.

## 402 entitlement (cloud)

The workspace's quota is exhausted. Report it and stop; the human upgrades or
waits for the reset. Never retry in a loop.

## 401 / expired workload token (cloud)

Re-authentication is the human's terminal work:

```bash
agentsecrets agent token rotate <token_id>   # overlap: old keeps working
agentsecrets agent token rotate <token_id> --compromise   # leaked: zero overlap
```

## Missing key

The name is not in `agentsecrets secrets list`. Never ask for the
value in chat. Give the human the value-blind forms (lifecycle.md, step 1)
and wait, then verify the name exists.

## Not initialized

`agentsecrets status` reports uninitialized. `agentsecrets
init` creates the human's account and key material. It is not a step you
perform for them.

## Audit chain fails to verify

`agentsecrets logs verify` reports a break. Treat it as a security
finding: stop, report the exact output, do not repair, do not continue the
session's work until the human decides.

## Redaction marker in output

Not a failure. `[REDACTED_BY_AGENTSECRETS]` (local) or
`[REDACTED]` (cloud) means an echoed value was scrubbed. Say so and
continue.
