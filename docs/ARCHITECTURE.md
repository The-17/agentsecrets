# AgentSecrets Architecture

This document explains the technical design of AgentSecrets, the first secrets manager built for AI-assisted development.

## Design Goals

1. **Zero-Knowledge Security**: Server never sees plaintext secrets
2. **AI-Native**: Works seamlessly with AI assistants
3. **Universal Compatibility**: Single binary works for all languages
4. **Simple UX**: One command to pull secrets
5. **Team-Friendly**: Built-in collaboration features

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User's Machine                        │
│                                                               │
│  ┌──────────────┐         ┌──────────────┐                  │
│  │ AI Assistant │         │     User     │                  │
│  │ (Claude/GPT) │         │              │                  │
│  └──────┬───────┘         └──────┬───────┘                  │
│         │                        │                           │
│         │  Commands (no values)  │  Commands                │
│         └────────────┬───────────┘                           │
│                      │                                       │
│              ┌───────▼────────┐                              │
│              │  agentsecrets  │                              │
│              │      CLI       │                              │
│              └───────┬────────┘                              │
│                      │                                       │
│         ┌────────────┼────────────┐                          │
│         │            │            │                          │
│    ┌────▼─────┐ ┌───▼────┐ ┌────▼─────┐                    │
│    │ Keyring  │ │ Config │ │ .env     │                    │
│    │ (Keys)   │ │        │ │ (Secrets)│                    │
│    └──────────┘ └────────┘ └──────────┘                    │
│                                                               │
└───────────────────────────┬───────────────────────────────────┘
                            │
                            │ HTTPS (TLS)
                            │
                    ┌───────▼───────┐
                    │               │
                    │  AgentSecrets │
                    │     API       │
                    │               │
                    └───────┬───────┘
                            │
                    ┌───────▼───────┐
                    │   Database    │
                    │  (Encrypted   │
                    │   Secrets)    │
                    └───────────────┘
```

## Component Breakdown

### 1. CLI (`cmd/agentsecrets/`)

**Purpose**: User-facing command-line interface

**Key Responsibilities**:
- Parse commands and flags
- Coordinate between packages
- Handle user interaction
- Output formatting

**Technology**: 
- Cobra (command framework)
- Supports subcommands: `init`, `login`, `workspace`, `project`, `secrets`

**Example**:
```go
var secretsPullCmd = &cobra.Command{
    Use:   "pull",
    Short: "Download secrets to .env file",
    Run: func(cmd *cobra.Command, args []string) {
        // 1. Load config
        // 2. Get current project
        // 3. Fetch encrypted secrets from API
        // 4. Decrypt locally
        // 5. Write to .env
    },
}
```

### 2. Crypto Package (`pkg/crypto/`)

**Purpose**: All encryption/decryption operations

**Key Responsibilities**:
- Generate key pairs (X25519)
- Encrypt/decrypt secrets (AES-256-GCM)
- Encrypt/decrypt workspace keys for team sharing (NaCl SealedBox)
- Derive password keys (Argon2id)

**Algorithms**:
- **X25519**: Elliptic curve keypair for asymmetric encryption
- **AES-256-GCM**: Symmetric encryption for secrets (replaces Fernet)
- **NaCl SealedBox**: Asymmetric encryption for workspace key wrapping
- **Argon2id**: Password-based key derivation (replaces PBKDF2)

**Key Hierarchy**:
```
Password → (Argon2id) → Password-Derived Key → decrypts Private Key
Private Key → (NaCl SealedBox) → decrypts Workspace Key
Workspace Key → (AES-256-GCM) → encrypts/decrypts Secrets
```

**Example**:
```go
// Encrypt a secret with workspace key
ciphertext, nonce, err := crypto.EncryptSecret("my-secret-value", workspaceKey)

// Decrypt a secret
plaintext, err := crypto.DecryptSecret(ciphertext, nonce, workspaceKey)
```

### 3. API Client (`pkg/api/`)

**Purpose**: Communication with the backend API

**API Strategy**: Reusing the existing SecretsCLI API (`https://secrets-api-orpin.vercel.app/api`) and modifying it as needed, rather than building a new API from scratch. The API is fundamentally "dumb storage" — it stores encrypted blobs and never sees plaintext. The only server-side crypto is personal workspace key creation during signup.

**Key Responsibilities**:
- Make HTTP requests
- Handle JWT authentication (access + refresh tokens)
- Serialize/deserialize JSON
- Endpoint resolution via dot-notation map (e.g., `"secrets.get"`)

**Example**:
```go
client := api.NewClient(config.GetAccessToken)
resp, err := client.Call("secrets.get", "GET", nil, map[string]string{
    "project_id": projectID,
    "key": "DATABASE_URL",
})
```

### 4. Config Package (`pkg/config/`)

**Purpose**: Local configuration management

**Stores**:
- API endpoint
- Current workspace ID
- Current project ID
- User email

**Location**: `~/.agentsecrets/config.json`

**Format**:
```json
{
  "api_endpoint": "https://api.agentsecrets.com/v1",
  "current_workspace": "ws_abc123",
  "current_project": "proj_xyz789",
  "user_email": "user@example.com"
}
```

### 5. Keyring Integration (`pkg/auth/`)

**Purpose**: Secure key storage using OS keychain

**Technology**: 
- macOS: Keychain
- Linux: Secret Service (GNOME Keyring, KWallet)
- Windows: Credential Manager

**Stores**:
- Private encryption key
- Authentication token

**Example**:
```go
import "github.com/zalando/go-keyring"

// Store private key
err := keyring.Set("agentsecrets", "private_key", encodedKey)

// Retrieve private key
key, err := keyring.Get("agentsecrets", "private_key")
```

## Security Architecture

### Encryption Flow

#### Uploading Secrets (Push)

```
1. User: agentsecrets secrets set DATABASE_URL=postgresql://...
                      ↓
2. Get workspace key from local cache
                      ↓
3. Encrypt secret with AES-256-GCM using workspace key
                      ↓
4. Upload encrypted blob + nonce to API
                      ↓
5. API stores blob — cannot decrypt (no workspace key)
```

#### Downloading Secrets (Pull)

```
1. User: agentsecrets secrets pull
                      ↓
2. Fetch encrypted blobs from API
                      ↓
3. Get workspace key from local cache
                      ↓
4. Decrypt each secret with AES-256-GCM
                      ↓
5. Write to .env file
```

### Key Management

**Key Hierarchy**:
- **User keypair** (X25519): Generated during `agentsecrets init`, private key stored in OS keychain
- **Workspace key** (random bytes): Encrypts/decrypts secrets, wrapped per-user with their public key
- **Password-derived key** (Argon2id): Encrypts private key for server-side backup/recovery

**Key Storage**:
- Private key → OS keychain (encrypted at rest by OS)
- Workspace keys → cached in `~/.agentsecrets/config.json` (decrypted at login)
- Never in .env files, never in plaintext on server

**Key Recovery**:
- 12-word mnemonic recovery code derived from private key
- Allows account recovery on new machines

### Zero-Knowledge Guarantee

The server **cannot** decrypt secrets because:
1. Secrets encrypted client-side with workspace key (AES-256-GCM)
2. Workspace key is wrapped per-user with their public key (NaCl SealedBox)
3. Server only stores encrypted blobs
4. Even with full database access, server can't decrypt

The one exception: the API creates and encrypts the personal workspace key during signup, using the user's public key. After this, all crypto is client-side.

## AI Integration Architecture

### How AI Uses AgentSecrets

```
┌─────────────────────────────────────────────────────────────┐
│                     AI Assistant (Claude)                   │
│                                                             │
│  "Pull production secrets for deployment"                   │
│                                                             │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────▼────────────────┐
         │  Execute bash command:         │
         │  agentsecrets secrets pull     │
         └───────────────┬────────────────┘
                         │
         ┌───────────────▼────────────────┐
         │  .env file created             │
         │  DATABASE_URL=postgresql://... │
         │  API_KEY=sk_live_...           │
         └───────────────┬────────────────┘
                         │
         ┌───────────────▼────────────────┐
         │  AI references by key:         │
         │  const db = process.env.       │
         │    DATABASE_URL                │
         └────────────────────────────────┘
```

**What AI Knows**: 
- Command to run (`agentsecrets secrets pull`)
- Secrets exist by key name (`DATABASE_URL`, `API_KEY`)
- .env file was created

**What AI Doesn't Know**:
- Actual secret values
- Contents of .env file
- Decryption keys

### Claude Skill Integration

The Claude skill teaches:
1. When to use AgentSecrets (deployment, setup, etc.)
2. Which commands to run
3. How to verify secrets are loaded
4. How to write code using secrets
5. **Never** to display secret values

See `skills/claude/SKILL.md` for full details.

## Data Models

### Workspace

```go
type Workspace struct {
    ID        string    `json:"id"`
    Name      string    `json:"name"`
    CreatedAt time.Time `json:"created_at"`
    Members   []Member  `json:"members"`
}

type Member struct {
    Email string `json:"email"`
    Role  string `json:"role"` // owner, admin, member
}
```

### Project

```go
type Project struct {
    ID          string    `json:"id"`
    Name        string    `json:"name"`
    WorkspaceID string    `json:"workspace_id"`
    CreatedAt   time.Time `json:"created_at"`
}
```

### Secret

```go
type Secret struct {
    Key       string    `json:"key"`        // e.g., "DATABASE_URL"
    Value     string    `json:"value"`      // Encrypted blob
    ProjectID string    `json:"project_id"`
    UpdatedAt time.Time `json:"updated_at"`
}
```

**Note**: `Value` is always encrypted. Server never sees plaintext.

## Building and Distribution

### Cross-Compilation

Go makes it easy to build for multiple platforms:

```bash
# macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -o agentsecrets-darwin-amd64

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o agentsecrets-darwin-arm64

# Linux
GOOS=linux GOARCH=amd64 go build -o agentsecrets-linux-amd64

# Windows
GOOS=windows GOARCH=amd64 go build -o agentsecrets-windows-amd64.exe
```

### Distribution Channels

1. **Direct Download**: GitHub Releases
2. **Homebrew**: `brew install agentsecrets`
3. **Python**: `pip install agentsecrets` (includes binary)
4. **npm**: `npm install -g @agentsecrets/cli` (includes binary)
5. **Docker**: `docker run agentsecrets/cli`

### Python/Node Wrappers

The Python/Node packages will:
1. Download appropriate binary for OS/arch
2. Provide thin wrapper around binary
3. Allow programmatic use if needed

```python
# Python wrapper
import agentsecrets

agentsecrets.login()
agentsecrets.secrets.pull("my-app")
```

## Performance Considerations

### Encryption Speed

AES-256-GCM is extremely fast (hardware-accelerated on modern CPUs):
- Encrypt 1000 secrets: ~5ms
- Decrypt 1000 secrets: ~5ms

No performance bottleneck for typical use (< 100 secrets).

### API Latency

Typical operations:
- Login: ~200ms
- Pull secrets: ~300ms (fetch + decrypt)
- Push secrets: ~400ms (encrypt + upload)

All acceptable for CLI use.

### Caching

Currently: No caching (always fetch fresh)

Future: Cache encrypted secrets locally, only fetch if changed (ETag support)

## Future Enhancements

### 1. Secret Rotation

```bash
agentsecrets secrets rotate DATABASE_URL
# Generates new value, updates everywhere
```

### 2. Audit Logging

```bash
agentsecrets audit log
# Shows who accessed what, when
```

### 3. Team Permissions

```go
type Member struct {
    Email string `json:"email"`
    Role  string `json:"role"`
    Permissions []Permission `json:"permissions"`
}
```

### 4. Web Dashboard

Visual interface for:
- Managing workspaces
- Viewing audit logs
- Inviting team members
- Rotating secrets

### 5. Git Integration

```bash
agentsecrets git protect
# Scans repo for exposed secrets
# Sets up pre-commit hooks
```

### 6. 1Password/Vault Import

```bash
agentsecrets import 1password
agentsecrets import vault
```

## Testing Strategy

### Unit Tests

Test each package in isolation:
- `pkg/crypto`: Encryption/decryption
- `pkg/config`: Load/save config
- `pkg/api`: HTTP client (mocked)

```bash
go test ./pkg/crypto
```

### Integration Tests

Test full workflows:
- `tests/integration/`: End-to-end scenarios

```bash
go test ./tests/integration
```

### Security Tests

- Verify encryption is actually happening
- Verify keys never leak
- Verify API can't decrypt
- Fuzzing for crypto functions

## Monitoring and Observability

Future:
- Client-side telemetry (opt-in)
- Error reporting (Sentry)
- Usage analytics
- Performance metrics

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development workflow.

Key points:
- All crypto changes require security review
- Test coverage: 80%+ target
- Benchmark performance-critical code
- Document public APIs

---

This architecture enables:
✅ Zero-knowledge security
✅ AI-native workflows  
✅ Universal compatibility
✅ Simple UX
✅ Team collaboration

All while keeping secrets secure and developers productive.