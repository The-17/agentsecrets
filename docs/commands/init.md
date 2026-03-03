# agentsecrets init

> Initialize AgentSecrets in the current project directory.

## Usage

```bash
agentsecrets init [--storage-mode 0|1]
```

## Description

`init` is the entry point. Run it once per machine (to create your account) and once per project directory (to link it to a remote project).

It does four things:

1. **Authenticates you** — create a new account or log in
2. **Sets up encryption** — generates your local keypair, downloads your workspace key
3. **Chooses a storage mode** — keychain or `.env` file
4. **Writes local config** — `.agentsecrets/project.json` and `.agent/workflows/agentsecrets.md`

## What Happens Step by Step

### If you don't have an account (signup)

1. Prompts for email + password
2. Generates an X25519 keypair client-side
3. Derives a key from your password with Argon2id
4. Encrypts your private key with the password-derived key
5. Sends public key + encrypted private key to the API
6. API creates your account, generates a workspace key, encrypts it with your public key, returns the encrypted copy
7. CLI decrypts the workspace key with your private key, caches it in `~/.agentsecrets/config.json`

Your private key never leaves your machine in plaintext.

### If you already have an account (login)

1. Prompts for email + password
2. Downloads your encrypted private key from the server
3. Derives the key from your password with Argon2id, decrypts the private key
4. Downloads your encrypted workspace keys, decrypts them with your private key
5. Caches workspace keys in `~/.agentsecrets/config.json`

### Storage Mode

```bash
agentsecrets init --storage-mode 1   # Keychain (recommended)
agentsecrets init --storage-mode 0   # Standard .env
```

| Mode | Secrets Go To | `.env` File Behavior |
|---|---|---|
| `1` — Keychain (default) | OS keychain (macOS Keychain / Windows Credential Manager / Secret Service) | `.env.example` created with key names only |
| `2` — Standard | Plaintext `.env` file | `.env` created and updated with values |

Keychain mode is more secure because secrets are tied to your OS user session, encrypted at rest by the OS, and never written to any file in your project.

### Files Written

**Global (once per machine):**
```
~/.agentsecrets/
  config.json          # workspace keys, active context, JWT token
  proxy.log            # audit log (appended by proxy/call/env)
```

**Project-local (once per directory):**
```
.agentsecrets/
  project.json         # project_id, workspace_id, storage_mode, last sync timestamps
.agent/
  workflows/
    agentsecrets.md    # AI assistant workflow file (teaches the agent how to use AgentSecrets)
```

`.agentsecrets/project.json` is safe to commit — it contains no credentials. It's the link between the directory and the remote project, just like a `.git/config` file.

`.agent/workflows/agentsecrets.md` is picked up automatically by any AI tool that reads workflow files (Claude, Gemini, Copilot, Cursor, etc.).

## Examples

```bash
# Interactive (prompts for all choices)
agentsecrets init

# Keychain mode, skip storage mode prompt (default)
agentsecrets init --storage-mode 1

# Standard .env mode, skip storage mode prompt
agentsecrets init --storage-mode 2

# Force reinitialize without confirmation prompt
agentsecrets init --force

# After running, verify state
agentsecrets status
```

## What It Does NOT Do

- It does not create a project — that's `agentsecrets project create`
- It does not store any secrets — that's `agentsecrets secrets set` or `agentsecrets secrets push`
- It does not configure the proxy or MCP — that's `agentsecrets proxy start` or `agentsecrets mcp install`

## Re-running on an Existing Install

If `~/.agentsecrets/config.json` already exists, `init` detects it and prompts:

```
⚠ AgentSecrets is already initialized.
Reinitialize? This will reset your config files.
  Yes
  No
```

Choosing **No** keeps everything as-is. Choosing **Yes** clears the existing session and config, then runs the full init flow again.

To skip the prompt and force reinitialize non-interactively:

```bash
agentsecrets init --force
```
