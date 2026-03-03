# agentsecrets workspace

> Manage team workspaces — members, roles, and the zero-trust domain allowlist.

## Subcommands

```
agentsecrets workspace list
agentsecrets workspace create <name>
agentsecrets workspace switch [name]
agentsecrets workspace members
agentsecrets workspace invite <email>
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
agentsecrets workspace invite alice@acme.com
```

Invites a user to the workspace. You are prompted for the role to assign (`admin` or `member`).

**What happens cryptographically:**
1. The CLI fetches Alice's public key from the server
2. Re-encrypts the workspace key with Alice's public key (NaCl SealedBox)
3. Sends the encrypted copy to the server for Alice to download at login

Alice's copy of the workspace key can only be decrypted with her private key (which is on her machine). The server never sees the plaintext workspace key.

*Requires: Admin or Owner role on the current workspace.*

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
DOMAIN
api.stripe.com
api.openai.com
api.sendgrid.com
maps.googleapis.com
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
