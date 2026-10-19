# agentsecrets migrate

> Direct server-to-server data migration between AgentSecrets Server instances.

## Usage

### Direct Server-to-Server (Recommended)
```bash
# 1. Generate ephemeral migration token on SOURCE server
agentsecrets server set https://api.agentsecrets.tech
agentsecrets login
agentsecrets migrate token

# 2. Tender token to DESTINATION server
agentsecrets server set https://api.agentsecrets.yourcompany.com
agentsecrets login
agentsecrets migrate --from https://api.agentsecrets.tech --token <MIGRATION_TOKEN>
```

### Airgapped / Offline Bundle Fallback
```bash
# Export bundle from source
agentsecrets migrate export --output bundle.json

# Import bundle to destination
agentsecrets migrate import bundle.json
```

---

## Key Guarantees

* **Zero-Knowledge Preserved**: Secret payloads remain encrypted under client-side workspace keys throughout export, transport, and import.
* **Direct Stream**: Destination server pulls directly from source server over TLS without disk file intermediary.

For full architectural deep dive, visit:
👉 **[Server Data Migration Guide](https://docs.agentsecrets.tech/api/migration)**
👉 **[CLI Migrate Reference](https://docs.agentsecrets.tech/workspaces/migration)**