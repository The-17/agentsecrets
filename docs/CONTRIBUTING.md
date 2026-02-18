# Contributing to AgentSecrets

Thanks for your interest in contributing! AgentSecrets is built in the open, and we welcome contributions from everyone.

## Quick Start

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/YOUR_USERNAME/agentsecrets
cd agentsecrets

# Install Go (1.21+)
# macOS: brew install go
# Linux: snap install go --classic
# Windows: Download from https://go.dev/dl/

# Download dependencies
go mod download

# Run the CLI
go run cmd/agentsecrets/main.go --help

# Run tests
go test ./...

# Build binary
go build -o agentsecrets cmd/agentsecrets/main.go
./agentsecrets --help
```

## Development Workflow

1. **Create a feature branch**: `git checkout -b feature/your-feature`
2. **Make changes**: Edit code, add tests
3. **Test**: Run `go test ./...`
4. **Format**: Run `go fmt ./...`
5. **Commit**: Use clear commit messages
6. **Push**: `git push origin feature/your-feature`
7. **PR**: Open a pull request on GitHub

## Code Style

We follow standard Go conventions:

- **Format**: Use `go fmt` (enforced in CI)
- **Linting**: Use `golangci-lint` (coming soon)
- **Naming**: 
  - Exported functions: `PascalCase`
  - Unexported functions: `camelCase`
  - Constants: `PascalCase` or `UPPER_CASE`
- **Errors**: Return errors, don't panic
- **Comments**: Public functions must have doc comments

## Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests verbosely
go test -v ./...

# Test specific package
go test ./pkg/crypto/...
```

## Project Structure

```
agentsecrets/
├── cmd/
│   └── agentsecrets/          # CLI entry point (main.go)
├── pkg/
│   ├── auth/                  # Authentication logic
│   ├── crypto/                # Encryption/decryption
│   ├── api/                   # API client
│   ├── workspace/             # Workspace management
│   ├── project/               # Project management
│   └── secrets/               # Secrets operations
├── skills/
│   ├── claude/                # Claude MCP skill
│   └── chatgpt/               # ChatGPT custom instructions
├── docs/                      # Documentation
├── scripts/                   # Build/release scripts
└── tests/                     # Integration tests
```


## What We Need Help With

### High Priority
- [ ] Multi-platform builds (macOS, Linux, Windows binaries)
- [ ] Error handling improvements
- [ ] Test coverage (aiming for 80%+)
- [ ] Documentation (examples, guides)

### Medium Priority
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Homebrew tap
- [ ] Python/npm wrapper packages
- [ ] Web dashboard (separate repo)

### Low Priority
- [ ] Secret rotation features
- [ ] Audit logging
- [ ] Team permissions
- [ ] SSO integration

## Commit Message Format

We use conventional commits:

```
feat: add secrets rotation command
fix: handle network errors gracefully
docs: update installation instructions
test: add crypto package tests
refactor: simplify workspace switching logic
chore: update dependencies
```

## Pull Request Guidelines

1. **Title**: Clear, descriptive (e.g., "Add secrets rotation command")
2. **Description**: 
   - What does this PR do?
   - Why is it needed?
   - How was it tested?
3. **Tests**: Add tests for new features
4. **Docs**: Update docs if needed
5. **Size**: Keep PRs focused and reasonably sized

## Questions?

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and ideas
- **Discord**: (coming soon)

## Learning Go?

Great resources:
- [A Tour of Go](https://go.dev/tour/)
- [Effective Go](https://go.dev/doc/effective_go)
- [Go by Example](https://gobyexample.com/)
- [Learn Go with Tests](https://quii.gitbook.io/learn-go-with-tests/)


## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thanks for contributing to making secrets management better for the AI era! 🚀