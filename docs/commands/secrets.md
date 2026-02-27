# `agentsecrets secrets`

The `secrets` sub-command comprises the core capability of AgentSecrets. It dictates how `.env` variables flow safely across development limits. 

## Command Overview

### `secrets list`
Downloads the encrypted environment mapping belonging to the linked `project.json` environment, explicitly decrypts them in memory against the Workspace Master Key, and visually outputs a `Key -> Value` mapping.

### `secrets pull [-f|--force]`
Fetches variables and generates physical schemas on the host OS.
- Calculates dynamic conflict patches mapping the remote state against what physically exists logically on the developer machine to prevent unexpected overwrite sequences.
- Respects `StorageMode` configuration (established in `init`).
  - **Standard**: Syncs values identically out to a root `./.env` file.
  - **Keychain**: Synchronizes variables directly against the host OS Keyring mapped by `project_id`, silently bypassing `.env` entirely. Only the skeleton blueprint `.env.example` file is actively modified.

### `secrets push`
Coordinates exactly modified state upward against the API server.
- The CLI bundles variables, aggressively encrypts them against the target Workspace context using robust AEAD constructions, and transmits binary payloads to the active server.
- Similar to `pull`, this logic dynamically references `StorageMode`. If Keychain mode is enabled, it pushes the differential values existing actively inside the Keychain layer.

### `secrets set [key] [value]`
Registers or actively modifies individual variables.

### `secrets delete [key]`
Completely excises variables and attempts to sync removals downstream against locally written files and global remote scopes.
