# Quick Start Guide

Get AgentSecrets running in 5 minutes.

## 1. Install Go

**macOS:**
```bash
brew install go
```

**Linux:**
```bash
sudo snap install go --classic
```

**Verify:**
```bash
go version  # Should show 1.21+
```

## 2. Clone and Build

```bash
# Clone the repo
git clone https://github.com/The-17/agentsecrets
cd agentsecrets

# Download dependencies
go mod download

# Build it
make build

# Or just run it
make run
```

## 3. Your First Commands

```bash
# Run the CLI
./bin/agentsecrets --help

# See version
./bin/agentsecrets version

# Try commands (will need API once backend is ready)
./bin/agentsecrets init
```

## 4. Run Tests

```bash
make test
```

## 5. Development Workflow

```bash
# Format code
make fmt

# Run tests
make test

# Build
make build

# All pre-commit checks
make pre-commit
```

## 6. Learn Go

New to Go? Read [GO_LEARNING_GUIDE.md](GO_LEARNING_GUIDE.md)

Use Claude Opus to help:
```
"Help me implement the login command"
"Explain how this crypto function works"
"Write tests for the config package"
```

## Common Tasks

### Add a New Command

1. Create file: `cmd/agentsecrets/mycommand.go`
2. Define command using Cobra
3. Add to root in `main.go`
4. Test it

Ask Claude: "Help me add a new command to AgentSecrets"

### Implement a Package Function

1. Add function to appropriate package (e.g., `pkg/crypto/`)
2. Write tests in `*_test.go`
3. Document with comments
4. Run `make test`

Ask Claude: "Help me implement secret encryption in the crypto package"

### Debug an Issue

1. Run with debug flag (when implemented)
2. Check error messages
3. Add print statements
4. Use Go debugger (Delve)

Ask Claude: "Why is this function returning an error?"

## Next Steps

- Read [CONTRIBUTING.md](CONTRIBUTING.md)
- Read [ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Check out [GO_LEARNING_GUIDE.md](GO_LEARNING_GUIDE.md)
- Look at the Claude skill in `skills/claude/SKILL.md`

## Getting Help

- **Claude Opus**: Your AI pair programmer
- **GitHub Issues**: Report bugs
- **Discussions**: Ask questions

Let's build the future of secrets management! 🚀