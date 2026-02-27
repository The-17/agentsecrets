# `agentsecrets init`

The `init` command is the absolute entry point for establishing a new project environment within the AgentSecrets ecosystem.

## Overview
When triggered, `init` walks you through an interactive sequence to authenticate (either by creating a new account or logging in to an existing one), establishes your preferred credential storage mechanism, and creates the foundational configuration files needed to link your current directory to an AgentSecrets remote project.

## Workflow

1. **Authentication (Login/Signup):** 
   If you do not have an active session cached in `~/.agentsecrets/token.json`, the CLI prompts you to select either `[Login]` or `[Create Account]`.
   - **Login**: Expects existing credentials. It pulls down your encrypted workspace keys from the API and decrypts them using your password.
   - **Signup**: Registers a brand new account, generates a local cryptographic keypair, encrypts your private key with your password, and immediately links a "personal" workspace to your account.

2. **Storage Mode Selection:**
   AgentSecrets manages environment variables differently depending on your security preferences. `init` interactsively asks you to choose a **Storage Mode**:
   - `Keychain (Recommended)`: Secrets are read/written exclusively to the encrypted OS-level keyring (macOS Keychain, Windows Credential Manager, Secret Service). The local `.env` file is intentionally kept blank, and only a `.env.example` mapping is generated.
   - `Standard Local Dev`: Secrets are written in plaintext to a local `.env` file, matching traditional workflows.

   You can skip the interactive prompt using the `--storage-mode` integer flag:
   ```bash
   # Initialize with OS Keychain storage (Mode 1)
   agentsecrets init --storage-mode 1
   
   # Initialize with Standard .env storage (Mode 2)
   agentsecrets init --storage-mode 2
   ```

3. **Project Binding Context:**
   If the chosen `StorageMode` succeeds, `init` automatically generates an `.agentsecrets/project.json` file in the current directory. This file tracks the remote `project_id` and tracks synchronisation timestamps like `last_pull` and `last_push`.

4. **Integration Scaffolding:**
   The `init` command also writes helper workflows into `.github/workflows/agentsecrets.yml` and explicitly drops an `.agents/workflows/agentsecrets.md` file designed to provide contextual system prompts about the CLI for other AI agents to digest.
