# agentsecrets environment

> Manage environments (development, staging, production) within your active project.

## Overview

AgentSecrets projects are partitioned into three environments by default: `development`, `staging`, and `production`. Your active environment determines which secrets are synced to your local OS keychain, and which external environment is modified when you use the `secrets pull` or `secrets push` commands.

## Usage

```bash
agentsecrets environment [command]
```

### Supported Commands

| Command | Description |
|---|---|
| `switch <environment>` | Switch the active environment |
| `list` | List all environments with their secret counts |
| `copy <from> <to>` | Instantly copy all secrets from one environment to another |
| `merge <from> <to>` | Merge structure and prompt for new values |
| `clean` | Delete all secrets in the current environment |

---

## Switching Environments

Switching environments automatically isolates your secret namespaces locally. Whenever you switch, you should perform a `pull` to fetch the destination environment's keys to your local machine.

```bash
agentsecrets environment switch staging
# Successfully switched to staging environment.

agentsecrets secrets pull
# Synced 12 secrets from cloud to OS keychain.
# This is environment scoped
```

---

## Listing Environments

See how many secrets exist in each external environment under your current active project.

```bash
agentsecrets environment list

# ENVIRONMENT      SECRETS
# development      12     <- active
# staging          14
# production       14
```

---

## Copying Secrets

If you're provisioning a new environment (such as initialising `staging` using your `development` tokens), you can copy all your secrets directly. This action will overwrite the destination environment if it already possesses values for the source keys.

```bash
agentsecrets environment copy development staging
# Copied 12 secrets from development to staging.

# In a script or an agent session there is no terminal to answer the prompt:
agentsecrets environment copy development staging --yes
```

`copy` asks before overwriting. When there is no terminal it refuses instead of
hanging or silently cancelling, and tells you to pass `--yes`.

---

## Comparing Secrets

To see what keys differ between two environments, use the `secrets diff` command with cross-environment flags. This will securely compare the values and tell you if they have drifted.

```bash
agentsecrets secrets diff --from development --to staging

# Key           Status
# STRIPE_KEY    Values differ
# AWS_KEY       Only in staging
#
# + 12 perfectly synced keys
```

---

## Merging Secrets

If you want to copy the *structure* (key names) of an environment but securely define *new values* for the destination (e.g., migrating variables from staging to production), use `merge`. The CLI will prompt you to enter the new value for each key sequentially.

```bash
agentsecrets environment merge staging production
# Key: DATABASE_URL
# Current value: postgresql://staging-db...
# Enter new value (or press Enter to keep current): postgresql://prod-db...
```

---

## Cleaning an Environment

To completely wipe an environment's secrets, use `clean`. This will securely delete all secrets from the cloud and automatically clear them from your local OS keychain.

```bash
agentsecrets environment clean
# Delete all secrets in development? (y/n): y
# Successfully cleaned development environment.
```
