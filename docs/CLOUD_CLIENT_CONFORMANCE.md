# Cloud client conformance

Every client that talks to the control plane or the cloud resolver must obey the
same invariants. There are six of them today, with the same trust boundary:
the server is untrusted at the transport layer. A response is data, never an
instruction to change where the next request goes or what shape of payload to
accept.

This document is the shared contract. The implementations live in four code
bases (Go CLI, MCP bridge TypeScript, plugin TypeScript, plugin Python). Each
carries its own test that fails before the invariant holds and passes after.

## The four clients

| Client | Surface | Entry point |
| --- | --- | --- |
| Go gateway | cloud `call`/proxy path | `pkg/gateway` `callCloud` |
| Go API | control-plane management | `pkg/api` `Client.Call` |
| MCP bridge (TS) | cloud mode | `integrations/mcp/src/resolver/client.ts` |
| Plugin (TS) | cloud resolver | `integrations/plugin/typescript/src/transports.ts` |
| Plugin (Python) | cloud resolver | `integrations/plugin/python/agentsecrets_plugin/transports.py` |

Three mode selectors decide which client runs (`gateway.Select`, MCP
`resolveMode`, plugin `env.ts`). Duplication is deliberate for zero-install
distribution; this contract is what stops the copies from drifting.

## Invariants

### C1. Never follow a redirect (client-side SSRF)
A 3xx from the control plane or resolver is a protocol error. Following it
resends the caller's credential (`Authorization` bearer) to a host that never
proved it owns the token. Every client must stop at the 3xx and fail closed.

- Go: `CheckRedirect` returns `http.ErrUseLastResponse`; `CallCtx` rejects 3xx
  before decoding the body.
- TS: `fetch(..., { redirect: 'manual' })` plus an explicit `isRedirect`
  rejection.
- Python: a urllib opener whose `redirect_request` returns `None`.

Tests: `TestCallCloudDoesNotFollowResolverRedirect`,
`TestFetchWorkloadEnvDoesNotFollowRedirect`, `TestClientDoesNotFollowRedirect`,
MCP `cloudResolve`/`controlCall` redirect tests, plugin-TS redirect test,
plugin-Python `test_does_not_follow_resolver_redirect`.

### C2. Reject malformed / non-JSON success bodies
A 2xx that is not the expected envelope must be rejected, not passed through to
the caller or the model. The server can answer with garbage; the client must not
trust it.

### C3. Fail closed on any transport error
Network failure, TLS failure, or timeout must surface as an error. There is no
plaintext fallback and no retry against an alternate host.

### C4. Decode only the documented envelope
The client reads `{status_code, headers, body}` (resolver) or `{data}` (control
plane) and nothing else. Unknown fields are ignored; missing required fields are
an error.

### C5. Refuse to send a credential to a non-authoritative host
The client must only ever address the configured control-plane / resolver
origin. A response that attempts to redirect or rewrite the target is covered by
C1; an explicit request to an unexpected host is rejected at the call site.

### C6. Bound the response body
A hostile or buggy resolver must not be able to exhaust client memory with an
arbitrarily large 2xx body. Every client reads through a 12 MiB cap and refuses
anything larger. An incomplete envelope (missing `status_code` for the resolver,
missing `{data}` for workload env) is an error, not a status-0 or empty success.

- Go: `io.LimitReader` in `gateway.callCloud` and `api.FetchWorkloadEnvSealed` (the
  sealed resolver env path), plus `status_code` / sealed-envelope validation.
- MCP TS: `readCapped` in `client.ts`, `status_code` validation in `cloudResolve`.
- Plugin TS / Python: `readCapped` / `_read_capped` in their transports.

Tests: Go `pkg/gateway/adversarial_test.go`, `pkg/api/adversarial_test.go`; MCP
`tests/client.test.ts`; plugin-TS `tests/transports.test.ts`; plugin-Python
`test_transports.py::test_refuses_oversized_body`.

## Adding a client

A new client (another language binding, a new mode) must satisfy C1–C6 and add a
test that fails before the invariant and passes after, in the same change. Drift
here is a security regression, not a style nit.

## Resolver-side responsibilities (out of scope for clients)

The resolver is the authoritative host. It owns SSRF defense for the *upstream*
it calls on the client's behalf: `target_url` allowlist, handle validation, and
scope enforcement. Those are server changes in `agentsecrets-cloud`, tracked
separately from this client contract.
