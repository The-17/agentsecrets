# `agentsecrets login`

The `login` command manages explicit authentication into an existing AgentSecrets account, completely bypassing the project initialization phases of `init`.

## Overview
Because AgentSecrets utilizes end-to-end encryption for team environments, "logging in" is conceptually heavier than just receiving a JWT from an API. Authentication involves securely decrypting your personal private key and deriving workspace keys.

## Workflow

1. **Credentials Parsing**: 
   The command prompts securely for an Email and Password.

2. **Session Verification**: 
   These exact credentials are sent to the `auth.login` API route.
   - A successful payload returns standard `access_token` and `refresh_token` JSON Web Tokens (JWTs).
   - It also returns the user's `encrypted_private_key`, `key_salt`, and an array of `encrypted_workspace_keys`.

3. **Cryptographic Validation**:
   - The CLI uses the user's plaintext password to derive a symmetric decryption key.
   - It uses this derived key to unlock the `encrypted_private_key` returned by the server.
   - Once the private key is decrypted, the CLI uses the private key to aggressively decrypt all of the user's associative Workspace keys.

4. **Caching & Keyring Storage**:
   - The user email, JWT tokens, and Base64-encoded Workspace keys are cached into `~/.agentsecrets/config.json`.
   - The highly-sensitive unlocked Private Key itself is stored exclusively inside the host OS's native Keychain.

## Silent Refreshing
When using any other commands (like `secrets pull`), you do not need to manually call `login` to receive a fresh API access token. 

AgentSecrets natively implements a Cobra `EnsureAuth` middleware hook. Before a command begins, if the local JWT calculates as expiring within 5 minutes, a `RefreshSession()` API background sequence is automatically scheduled—the terminal will output "Refreshing expired session token..." before seamlessly running your command with the un-staled credentials.
