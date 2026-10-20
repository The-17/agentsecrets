# Account vault and recovery keys

The vault is the client-side root of an AgentSecrets account. It lets you add
or change how you unlock your account without ever letting the server decrypt
anything.

## What the server stores

The server stores two things per account:

- the opaque vault record (ciphertext plus metadata), and
- the legacy encrypted private-key blob that older clients already use.

It never stores the vault key, the recovery key, or a plaintext private key.
Every unwrap happens on the client.

## How it works

A random 32-byte vault key (VK) is generated once at vault creation and never
derived from a password. The account's X25519 private key is encrypted under
the VK. The VK is then wrapped once per unlock factor, so every factor unlocks
the same vault:

| Factor | Key-encryption key |
|---|---|
| `password` envelope | `Argon2id(password, salt_p)` |
| `recovery` envelope | `HKDF(recovery_key, salt_r)` |
| `passkey` envelope | `HKDF(WebAuthn PRF(passkey, salt_i), credential_id)` |
| `bridge` blob | `HKDF(X25519 private key, salt_b)` |

The bridge is a separate sealed blob, not an envelope, so `vault status` lists
`password` and `recovery` only. It exists for cross-version compatibility. It
lets a newer client re-wrap the vault after an older client changes the
password without updating the vault.

Every unwrap is bound to the account id through length-prefixed AAD, so a vault
copied to another account fails to open. The operator's AAD is never built from
JSON key order.

### Integrity and concurrency

The client signs the vault root with an Ed25519 key derived from the VK. The
proof covers the vault version, the sealed private key, the bridge, and each
envelope's id, type, and ciphertext. The server verifies that proof before it
stores an update.

The proof public key is pinned per account on first successful unlock. A later
vault with a different proof key is rejected even if its own signature is valid,
which catches a rollback or a substituted vault.

Updates use optimistic concurrency: the client sends `expected_version`, the
server accepts only the vault whose `vault_version` matches, and the write is
atomic. A concurrent update gets `409` and the client retries.

## Recovery key

The recovery key is one 256-bit key encoded as Crockford base32 with four
checksum characters, grouped for transcription. It is:

- shown once, when the vault is created or rotated,
- never sent to the server,
- never consumed, so it keeps working until you rotate it, and
- rotated in two phases: the new key is added and uploaded first, and the old
  key is retired only after you confirm you saved the new one.

If you abort a rotation, both keys still work until you finish or retry. Losing
every factor means the account cannot be recovered. There is no server-side
escrow and no recovery backdoor.

Removing the password factor requires a confirmed recovery key. A passkey alone
is not sufficient in this release.

The CLI has no password-less sign-in yet. The password envelope, the recovery
envelope, and the bridge are all proven to unlock the same vault in
`pkg/vault`, but obtaining a session still requires the password. Until OPAQUE
or OAuth separates identity from unlock, a forgotten password is not recovered
from the CLI, and the recovery key's value is that it is already in place for
that next phase.

## Server endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/auth/vault/` | Read the vault and its version |
| `PUT` | `/api/auth/vault/` | Replace the vault with `expected_version` (CAS) |
| `PATCH` | `/api/auth/change-password/` | Update the legacy blob and, optionally, the vault in one transaction |

A server that does not implement these routes returns `404` or `405`. The CLI
treats that as "vault not supported yet", prints a warning, and continues on the
legacy key path.

## CLI

```bash
agentsecrets init                 # creates the vault and shows the recovery key once
agentsecrets login                # unlocks the vault, or migrates a legacy account
agentsecrets vault status         # envelopes and whether the recovery key is confirmed
agentsecrets vault recovery rotate
agentsecrets password change
```

On signup and on the first login of a legacy account, the CLI prints the
recovery key and asks you to confirm you saved it. Confirmation is a separate
signed update, so the server knows the recovery factor is usable before the
password can ever be removed.

## Migration and rollout

Migration is add-only.

1. The CLI logs in exactly as before.
2. It uploads the vault only after login, with `PUT /api/auth/vault/`.
3. If that route is missing, it skips migration and the account stays on the
   legacy key.
4. The legacy blob is never deleted.

This means the new CLI works against both old and new servers. The server can
deploy first. Old CLI versions keep working against the new server because the
login response only gained fields and the vault routes are additive.

Old clients that change a password update only the legacy blob. On the next
login the new CLI opens the bridge with the private key, re-wraps the password
envelope under the new password, and uploads the repaired vault.

Sunset the legacy blob no earlier than 12 months after the first CLI release
that writes vaults, or when old-client traffic falls below 1%. The bridge is
removed only after the legacy blob is gone.

## Limits you should know

- **The server sees the password at login.** It cannot derive the VK from it
  today, but an actively malicious server could capture it and use the legacy
  blob and bridge. OPAQUE or full OAuth removes that exposure. Until then, the
  vault is stronger against a server that stores data and later leaks it than
  against a server that is actively hostile at login time.
- **The legacy blob keeps the old offline brute-force surface** until it is
  sunset.
- **Passkeys are specified but not shipped.** The CLI rejects a passkey-only
  account with a clear message rather than guessing.
- **Password reset without a factor is not a recovery path.** Email-based
  forgotten-password recovery and the 30-day disabled-account retention window
  are design work, not implemented behavior.
- **Losing every factor is unrecoverable.** That is the cost of having no
  escrow.

## Next

- Passkey envelope with the WebAuthn PRF ceremony.
- OPAQUE so the server never sees the password.
- Email-based recovery that still cannot decrypt the vault.
- Legacy blob sunset and bridge removal.
