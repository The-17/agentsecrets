# agentsecrets status

> Inspect session state, active project context, server connection, and keychain-auth daemon health.

## Usage

```bash
agentsecrets status
```

---

## Output Fields

* **CLI Version & Build**: Running version plus update verdict (`up to date`, `outdated, <version> available`, or `dev build`).
* **Server Endpoint**: Target server URL and resolution source (Default vs. Self-Hosted).
* **Workspace & Project**: Active workspace role, project binding, and environment branch.
* **Keychain Backend**: `keychain-auth` daemon connection status and binary attestation state.

For complete status options and troubleshooting, visit:
👉 **[System Status Documentation](https://docs.agentsecrets.tech/cli/status)**

## Troubleshooting System Health

If `agentsecrets status` indicates that the keychain daemon is inactive or authorization has failed:

```bash
agentsecrets doctor
```

The doctor command performs a complete 8-point audit of local security components and automatically self-heals broken state.
