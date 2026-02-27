# `agentsecrets logout`

The `logout` command cleanly terminates an active session and wipes cached credentials off the host filesystem.

## Overview
Because the CLI caches sensitive Private Keys inside the OS Keyring and JWT tracking tokens inside `~/.agentsecrets/`, switching development accounts or purging compromised machines mandates a strict `logout` loop.

## Behavior

1. **Remote De-Authorization**:
   The CLI fires a best-effort `POST` request to the `auth.logout` API endpoint. If reachable, this forces the backend to block the associated `refresh_token` from generating subsequent valid sessions.

2. **Keyring Purge**:
   The `logout` flow invokes the underlying OS keyring bindings to aggressively scrub the user's securely-stored Private Key mappings.

3. **Filesystem Purge**:
   The command targets `~/.agentsecrets/config.json` and `~/.agentsecrets/token.json`. It completely overwrites their contents with empty JSON object maps, explicitly stripping email caches, workspace routing bindings, and JWTs.

> **Note:** Executing `logout` only clears *global* credentials. It explicitly does **not** erase the local project linkages found inside `./.agentsecrets/project.json`. This ensures that logging out and back in does not forcefully un-bind the current directory from the remote synchronization tree.
