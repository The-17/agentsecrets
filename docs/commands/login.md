# agentsecrets login

> Authenticate to an existing AgentSecrets account.

## Usage

```bash
agentsecrets login
```

## Description

`login` re-authenticates on a machine where you already have an account. Unlike `init`, it skips project setup — it only restores your session and decrypts your workspace keys.

Use `login` when:
- Your session expired and you're prompted to authenticate
- You're setting up AgentSecrets on a second machine
- You logged out and want to log back in

---

## What Happens

Login is more than a JWT exchange. Because secrets are encrypted with workspace keys that are themselves encrypted with your private key, login involves a full cryptographic key unwrapping sequence:

**1. Credential submission**  
Prompts for email and password. Sends them to the `auth.login` API endpoint.

**2. Server response**  
The server returns:
- `access_token` and `refresh_token` (JWTs)
- `encrypted_private_key` — your private key, encrypted with an Argon2id-derived key from your password
- `key_salt` — the Argon2id salt used to derive the key
- `encrypted_workspace_keys` — one encrypted workspace key per workspace you belong to

**3. Private key decryption**  
The CLI uses your password to derive a symmetric key with Argon2id:

```
password + key_salt → (Argon2id) → derived_key
derived_key → (AES-256-GCM decrypt) → private_key
```

**4. Workspace key decryption**  
For each workspace:

```
private_key → (NaCl SealedBox open) → workspace_key
```

**5. Caching**  
- Private key → OS keychain (encrypted by OS)
- Workspace keys (decrypted in memory) → `~/.agentsecrets/config.json`
- JWT tokens → `~/.agentsecrets/config.json`

Your password is used only during this step and then discarded. It is never stored anywhere.

---

## Automatic Token Refresh

You rarely need to call `login` manually. AgentSecrets attaches an `EnsureAuth` middleware to every command. Before each command runs, it checks the JWT expiry:

- If the token is valid → proceed
- If expiring within 5 minutes → silently call `POST /auth/refresh` with the refresh token, get a new access token, cache it, proceed
- If both tokens are expired → prompt for re-authentication

This means `agentsecrets secrets pull` at 3am after a long session still works — the refresh happens transparently.

---

## Multi-Machine Setup

On a second machine:

```bash
agentsecrets login     # decrypts your keys from the server, sets up keychain
agentsecrets status    # verify workspace context
cd your-project/
agentsecrets project use my-backend   # link the directory
agentsecrets secrets pull             # pull secrets to keychain
```

No need to re-run `init` unless you want to create a new project.
