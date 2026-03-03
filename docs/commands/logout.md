# agentsecrets logout

> Clear your session and remove cached credentials from this machine.

## Usage

```bash
agentsecrets logout
```

## Description

`logout` terminates your session on the current machine and wipes all locally cached credentials. It does not affect other machines, team members, or your stored secrets, only the local session.

---

## What Gets Cleared

`logout` operates in three steps:

**1. Remote invalidation (best-effort)**  
Sends a `POST` to `auth.logout`. If the server is reachable, it invalidates the refresh token, preventing it from being used to generate new access tokens. If the server is unreachable (offline, network issue), logout still proceeds locally.

**2. OS keychain purge**  
Removes the private key from the OS keychain:
- macOS: deletes the Keychain entry
- Windows: removes the Credential Manager entry
- Linux: removes the Secret Service entry

**3. Config wipe**  
Clears `~/.agentsecrets/config.json` of:
- JWT access and refresh tokens
- Cached workspace keys
- User email and workspace bindings

---

## What Is NOT Cleared

- **`.agentsecrets/project.json`** in any project directory — your project links remain intact. Logging back in and running `agentsecrets secrets pull` restores everything immediately.
- **Secrets in the OS keychain** — secret values stored by `secrets pull` (keyed by project ID) are not removed. They remain available for `agentsecrets env` even after logout, until they are explicitly deleted with `agentsecrets secrets delete`.
- **Remote data** — your secrets, workspace, and team remain on the server, encrypted.

---

## When to Use

```bash
# Switching to a different account
agentsecrets logout
agentsecrets login   # or agentsecrets init for a new account

# Shared machine — end of session
agentsecrets logout

# After a credential-related security incident
agentsecrets logout
# Then rotate the affected secrets:
agentsecrets secrets set COMPROMISED_KEY=new_value
```

---

## After Logout

To resume work on any machine:

```bash
agentsecrets login
agentsecrets secrets pull   # restores secrets to keychain
```

Your secrets are still encrypted on the server. Nothing is lost.
