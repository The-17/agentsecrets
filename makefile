.PHONY: help build test run clean install fmt lint dev release

# Variables
BINARY_NAME=agentsecrets
VERSION?=0.1.0
BUILD_DIR=bin
GO=go
GOFMT=gofmt
GOLINT=golangci-lint

# Default target
help:
	@echo "AgentSecrets - Build Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build       Build the binary for current OS"
	@echo "  test        Run all tests"
	@echo "  run         Build and run the CLI"
	@echo "  clean       Remove build artifacts"
	@echo "  install     Install binary to system"
	@echo "  fmt         Format all Go code"
	@echo "  lint        Run linters"
	@echo "  dev         Run in development mode (with hot reload)"
	@echo "  release     Build binaries for all platforms"
	@echo "  help        Show this help message"

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME) cmd/agentsecrets/main.go
	@echo "✓ Built $(BUILD_DIR)/$(BINARY_NAME)"

# Run tests
test:
	@echo "Running tests..."
	$(GO) test -v -cover ./...

# Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report: coverage.html"

# Build and run
run: build
	@echo "Running $(BINARY_NAME)..."
	./$(BUILD_DIR)/$(BINARY_NAME)

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html
	@echo "✓ Cleaned"

# Install to system
install: build
	@echo "Installing $(BINARY_NAME)..."
	@cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "✓ Installed to /usr/local/bin/$(BINARY_NAME)"

# Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) -w -s .
	@echo "✓ Code formatted"

# Run linters (requires golangci-lint)
lint:
	@echo "Running linters..."
	@which $(GOLINT) > /dev/null || (echo "golangci-lint not installed. Install: brew install golangci-lint" && exit 1)
	$(GOLINT) run ./...
	@echo "✓ Linting complete"

# Development mode (auto-rebuild on changes)
dev:
	@echo "Development mode (Ctrl+C to stop)"
	@which air > /dev/null || (echo "air not installed. Install: go install github.com/cosmtrek/air@latest" && exit 1)
	air

# Build for all platforms
release:
	@echo "Building release binaries..."
	@mkdir -p $(BUILD_DIR)/releases
	
	# macOS Intel
	GOOS=darwin GOARCH=amd64 $(GO) build -ldflags "-X main.version=$(VERSION)" \
		-o $(BUILD_DIR)/releases/$(BINARY_NAME)-$(VERSION)-darwin-amd64 cmd/agentsecrets/main.go
	
	# macOS Apple Silicon
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "-X main.version=$(VERSION)" \
		-o $(BUILD_DIR)/releases/$(BINARY_NAME)-$(VERSION)-darwin-arm64 cmd/agentsecrets/main.go
	
	# Linux
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "-X main.version=$(VERSION)" \
		-o $(BUILD_DIR)/releases/$(BINARY_NAME)-$(VERSION)-linux-amd64 cmd/agentsecrets/main.go
	
	# Linux ARM
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "-X main.version=$(VERSION)" \
		-o $(BUILD_DIR)/releases/$(BINARY_NAME)-$(VERSION)-linux-arm64 cmd/agentsecrets/main.go
	
	# Windows
	GOOS=windows GOARCH=amd64 $(GO) build -ldflags "-X main.version=$(VERSION)" \
		-o $(BUILD_DIR)/releases/$(BINARY_NAME)-$(VERSION)-windows-amd64.exe cmd/agentsecrets/main.go
	
	@echo "✓ Release binaries built in $(BUILD_DIR)/releases/"
	@ls -lh $(BUILD_DIR)/releases/

# Quick checks before committing
pre-commit: fmt test lint
	@echo "✓ All pre-commit checks passed"

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GO) mod download
	$(GO) mod verify
	@echo "✓ Dependencies downloaded"

# Update dependencies
update-deps:
	@echo "Updating dependencies..."
	$(GO) get -u ./...
	$(GO) mod tidy
	@echo "✓ Dependencies updated"