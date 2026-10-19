# agentsecrets allowlist

> Manage workspace-level zero-trust egress domain allowlists for the credential proxy and AI agents.

## Usage

```bash
# Add authorized outbound domains
agentsecrets allowlist add api.stripe.com api.openai.com

# List authorized domains
agentsecrets allowlist list

# Remove an authorized domain
agentsecrets allowlist remove api.stripe.com
```

---

## Security Model

The proxy checks the outbound domain against the allowlist **before** resolving any secret from the OS keychain. If a domain is not allowlisted, the request is immediately rejected with HTTP 403.

For complete policy options and configuration, visit:
👉 **[Domain Allowlist Documentation](https://docs.agentsecrets.tech/workspaces/allowlist)**
👉 **[Proxy Security Architecture](https://docs.agentsecrets.tech/proxy/domain-allowlist)**