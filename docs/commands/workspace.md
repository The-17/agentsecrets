# agentsecrets workspace

> Manage team workspaces — members, roles, and the zero-trust domain allowlist.

## Subcommands

```
agentsecrets workspace list
agentsecrets workspace refresh
agentsecrets workspace create <name>
agentsecrets workspace switch [name]
agentsecrets workspace members
agentsecrets workspace invite <email...>
agentsecrets workspace remove <email>
agentsecrets workspace promote <email>
agentsecrets workspace demote <email>
agentsecrets workspace allowlist add <domain> [domain...]
agentsecrets workspace allowlist list
agentsecrets workspace allowlist log
```

---

## Overview

A **workspace** is the top-level organizational boundary in AgentSecrets. Think of it as a team or organization. It contains:
- **Projects** — partitioned sets of secrets (e.g., `backend`, `mobile`, `infra`)
- **Members** — users with access to the workspace
- **An allowlist** — the domains the proxy is allowed to reach

When you create an account, a personal workspace is created automatically. You can create additional shared workspaces for teams.

---

## workspace list

```bash
agentsecrets workspace list
```

Lists all workspaces you have access to. The active workspace is marked with `→`.

The list is rendered from a local cache so it returns instantly and works offline.
The cache is reconciled with the server at most once every 60 seconds: if your
memberships changed (a new invitation, a role change, a workspace you were
removed from), the command prints what moved and the updated list.

| Flag | Effect |
|---|---|
| `--offline` | Use the cache only. No network call at all. |
| `--refresh` | Reconcile with the server even if the cache is fresh. |

An invitation only becomes visible once the membership is **active**. Invitations
sent from the CLI carry an encrypted copy of the workspace key, so they are
active immediately. An invitation sent without that key stays `invited` and
cannot be accepted from the CLI yet; re-send it with `workspace invite` from an
admin account.

---

## workspace refresh

```bash
agentsecrets workspace refresh
```

Fetches your memberships again, decrypts the workspace key for any workspace you
have just gained access to, and updates the local cache. Use it right after being
invited instead of logging out and back in.

The private key needed to unwrap a newly shared workspace key is already in your
OS keyring, so this needs no password and no re-authentication. A workspace whose
key cannot be unwrapped keeps the key you already hold rather than disappearing
from the cache.


```
→  My Projects        (ws_abc123)  personal
   Acme Corp         (ws_def456)  shared
   Side Project      (ws_ghi789)  shared
```

---

## workspace create

```bash
agentsecrets workspace create "Acme Backend Team"
```

Creates a new shared workspace and immediately switches to it. Any projects created after this point belong to the new workspace.

---

## workspace switch

```bash
agentsecrets workspace switch "Acme Backend Team"
agentsecrets workspace switch   # interactive picker
```

Sets the active workspace. All subsequent `project` and `secrets` operations operate within the selected workspace. Updates `current_workspace_id` in `~/.agentsecrets/config.json`.

---

## workspace members

```bash
agentsecrets workspace members
```

Lists all members of the current workspace:

```
EMAIL                    STATUS    ROLE
you@example.com          active    owner
alice@acme.com           active    admin
bob@acme.com             pending   member
```

---

## workspace invite

```bash
agentsecrets workspace invite alice@acme.com bob@acme.com
```

Invites one or more users to the workspace simultaneously. You are prompted for the role to assign (`admin` or `member`).

**This command requires:**
- Admin or Owner role
- Your account password (prompted interactively) to decrypt the workspace key locally

**What happens cryptographically:**
1. The CLI prompts for your local password to decrypt the symmetric workspace key.
2. The CLI concurrently fetches Alice's and Bob's public keys from the server.
3. The CLI encrypts a copy of the workspace key for each invitee using their public key (NaCl SealedBox).
4. Sends the encrypted envelopes to the server in a single bulk request.

When Alice and Bob accept their invitations and run `agentsecrets login`, their clients retrieve their respective envelopes, decrypting them using their local private keys to gain access to the workspace.

---

## workspace remove

```bash
agentsecrets workspace remove bob@acme.com
```

Removes a member from the workspace. They immediately lose access to all projects within it.

Prompts for confirmation before executing.

*Requires: Admin or Owner role.*

---

## workspace promote

```bash
agentsecrets workspace promote alice@acme.com
```

Grants Alice the **admin** role. Admins can:
- Invite and remove members
- Promote and demote other members
- Modify the workspace allowlist (requires password)

*Requires: Owner role.*

---

## workspace demote

```bash
agentsecrets workspace demote alice@acme.com
```

Revokes Alice's admin role, returning her to **member** status.

*Requires: Owner role.*

---

## workspace allowlist add

```bash
agentsecrets workspace allowlist add api.stripe.com
agentsecrets workspace allowlist add api.stripe.com api.openai.com api.sendgrid.com
```

Adds one or more domains to the workspace's zero-trust allowlist. The proxy enforces this list — any request to a domain not on the allowlist is blocked with 403 Forbidden.

**This command requires:**
- Admin or Owner role
- Your account password (prompted interactively)

The password requirement ensures physical presence — an agent operating the CLI autonomously cannot modify the allowlist on its own.

**Domain matching:** The domain must be an exact match on the hostname. `api.stripe.com` does not automatically allow `uploads.stripe.com`.

---

## workspace allowlist list

```bash
agentsecrets workspace allowlist list
```

Shows the full allowlist for the current workspace:

```
DOMAIN                ADDED BY              ADDED AT
api.stripe.com        you@example.com       2026-03-01 14:23
api.openai.com        alice@acme.com        2026-03-15 09:10
api.sendgrid.com      you@example.com       2026-04-01 11:45
```

---

## workspace allowlist log

```bash
agentsecrets workspace allowlist log
agentsecrets workspace allowlist log --last 20
```

Shows recent allowlist activity — domains that were added, removed, or triggered a block at the proxy.

Useful for auditing what domains have been accessed or blocked.

---

## Role Reference

| Action | Member | Admin | Owner |
|---|---|---|---|
| List workspaces / projects / secrets | ✅ | ✅ | ✅ |
| Pull / push secrets | ✅ | ✅ | ✅ |
| Invite members | ❌ | ✅ | ✅ |
| Remove members | ❌ | ✅ | ✅ |
| Modify allowlist | ❌ | ✅ + password | ✅ + password |
| Promote / demote admins | ❌ | ❌ | ✅ |
| Delete workspace | ❌ | ❌ | ✅ |
