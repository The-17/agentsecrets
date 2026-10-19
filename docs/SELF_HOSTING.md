# Self-Hosting AgentSecrets Server

> Guide for deploying private instances of `agentsecrets-server` and configuring the AgentSecrets CLI.

---

## Architecture Overview

`agentsecrets-server` is an asynchronous Django Ninja Extra backend running on ASGI (Uvicorn/Gunicorn) with PostgreSQL 16+.

* **Zero-Knowledge Core**: Secrets are encrypted client-side with AES-256-GCM. The server stores only ciphertext blobs and never sees plaintext secret values.
* **Server Envelope Encryption**: Stored blobs are protected with an outer Fernet encryption key (`ENCRYPTION_KEY`).

---

## 1. Quick Start with Docker Compose

Clone and run the open-source backend:

```bash
git clone https://github.com/The-17/agentsecrets-server.git
cd agentsecrets-server

# Generate required secrets
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Create .env file
cat <<EOF > .env
SETTINGS=core.settings.prod
SECRET_KEY=$SECRET_KEY
ENCRYPTION_KEY=$ENCRYPTION_KEY
ALLOWED_HOSTS=*
POSTGRES_DB=agentsecrets
POSTGRES_USER=postgres
POSTGRES_PASSWORD=secure-db-password
POSTGRES_HOST=db
POSTGRES_PORT=5432
RUN_MIGRATIONS=true
COLLECT_STATIC=true
EOF

# Start services
docker-compose up -d
```

---

## 2. Zero-Disk Hardening: Ingest & Delete `.env`

Once your server is running, never leave plaintext `.env` files on disk:

```bash
# 1. Point CLI to your self-hosted instance
agentsecrets server set http://localhost:8000
agentsecrets init

# 2. Ingest the .env into your self-hosted server
agentsecrets project create agentsecrets-server
agentsecrets secrets push

# 3. Securely delete the plaintext .env file
rm .env

# 4. Run future containers with in-memory injection
agentsecrets exec -- docker-compose up -d
```

---

## 3. Connecting the Official AgentSecrets CLI

The official AgentSecrets CLI works natively with both the default server and any self-hosted instance.

### Global Configuration (All Repositories)
```bash
agentsecrets server set https://api.agentsecrets.yourcompany.com
```

### Project-Specific Override
To pin a specific repository to your self-hosted server:
```bash
agentsecrets server set https://api.agentsecrets.yourcompany.com --project
```

### Interactive Init / Login Wizard
```bash
agentsecrets init --server https://api.agentsecrets.yourcompany.com
# Or select option 2 when running interactive `agentsecrets init`
```

### CI/CD Environment Variable
```bash
export AGENTSECRETS_SERVER_URL="https://api.agentsecrets.yourcompany.com"
```

### Check Connection & Latency
```bash
agentsecrets server status
agentsecrets status
```

### Reset Back to Default Server
```bash
agentsecrets server reset
```

---
 
## 4. Official Documentation & Production Runbooks

For production Linux systemd deployment, Nginx/Caddy TLS setup, Kubernetes manifests, and key rotation procedures, visit:
👉 **[Self-Hosting Operations Manual](https://docs.agentsecrets.tech/guides/self-hosting)**
👉 **[Server Architecture & Deployment](https://docs.agentsecrets.tech/api/self-hosting)**
👉 **[CLI Server Command Reference](https://docs.agentsecrets.tech/cli/server)**

---

## Troubleshooting

If you encounter keychain authorization errors when linking to your self-hosted server:

```bash
agentsecrets doctor
```
