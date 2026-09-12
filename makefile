.PHONY: help build envguard test run clean install fmt lint dev release

# Variables
BINARY_NAME=agentsecrets
VERSION?=3.1.5
BUILD_DIR=bin
GO=go
GOFMT=gofmt
GOLINT=golangci-lint
CC?=cc

# Host OS and Go arch, used to pick the right env-guard interposer to build.
UNAME_S := $(shell uname -s 2>/dev/null)
GUARD_ARCH := $(shell $(GO) env GOARCH 2>/dev/null)

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

# Build the env-guard interposer for the host OS. It is loaded into children
# spawned by `agentsecrets env` to mark them un-attachable and redact secret
# output. If no compiler is available the build still succeeds; children then run
# with parent-side masking only. The output name must match envguard.libraryName()
# for the host (guard_<os>_<arch>.{so,dylib}).
envguard:
	@echo "Building env-guard interposer..."
	@mkdir -p $(BUILD_DIR)
ifeq ($(UNAME_S),Darwin)
	@if command -v clang >/dev/null 2>&1; then \
		clang -dynamiclib -O2 -o $(BUILD_DIR)/guard_darwin_$(GUARD_ARCH).dylib internal/envguard/csrc/guard_darwin.c && \
		codesign -s - $(BUILD_DIR)/guard_darwin_$(GUARD_ARCH).dylib >/dev/null 2>&1; \
		echo "✓ Built $(BUILD_DIR)/guard_darwin_$(GUARD_ARCH).dylib (ad-hoc signed)"; \
	else \
		echo "⚠ No clang; env-guard not built — env children run with parent-side masking only"; \
	fi
else ifeq ($(UNAME_S),Linux)
	@if command -v $(CC) >/dev/null 2>&1; then \
		$(CC) -shared -fPIC -O2 -o $(BUILD_DIR)/guard_linux_$(GUARD_ARCH).so internal/envguard/csrc/guard_linux.c && \
		echo "✓ Built $(BUILD_DIR)/guard_linux_$(GUARD_ARCH).so"; \
	else \
		echo "⚠ No C compiler ($(CC)); env-guard not built — env children run with parent-side masking only"; \
	fi
else
	@echo "⚠ env-guard interposer not built on $(UNAME_S) — env children run with parent-side masking only"
endif

# Build the binary
build: envguard
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build -trimpath -ldflags "-s -w -X github.com/The-17/agentsecrets/cmd/agentsecrets/commands.Version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/agentsecrets/
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
	GOOS=darwin GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w -X github.com/The-17/agentsecrets/cmd/agentsecrets/commands.Version=$(VERSION)" \
		-o $(BUILD_DIR)/releases/$(BINARY_NAME)-$(VERSION)-darwin-amd64 ./cmd/agentsecrets/

	# macOS Apple Silicon
	GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags "-s -w -X github.com/The-17/agentsecrets/cmd/agentsecrets/commands.Version=$(VERSION)" \
		-o $(BUILD_DIR)/releases/$(BINARY_NAME)-$(VERSION)-darwin-arm64 ./cmd/agentsecrets/

	# Linux
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w -X github.com/The-17/agentsecrets/cmd/agentsecrets/commands.Version=$(VERSION)" \
		-o $(BUILD_DIR)/releases/$(BINARY_NAME)-$(VERSION)-linux-amd64 ./cmd/agentsecrets/

	# Linux ARM
	GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "-s -w -X github.com/The-17/agentsecrets/cmd/agentsecrets/commands.Version=$(VERSION)" \
		-o $(BUILD_DIR)/releases/$(BINARY_NAME)-$(VERSION)-linux-arm64 ./cmd/agentsecrets/

	# Windows
	GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w -X github.com/The-17/agentsecrets/cmd/agentsecrets/commands.Version=$(VERSION)" \
		-o $(BUILD_DIR)/releases/$(BINARY_NAME)-$(VERSION)-windows-amd64.exe ./cmd/agentsecrets/
	
	@echo "✓ Release binaries built in $(BUILD_DIR)/releases/"
	@ls -lh $(BUILD_DIR)/releases/

# Check compilation across all three major platforms
build-all:
	@echo "Checking compilation across platforms..."
	@echo -n "  Linux (amd64)... "
	@GOOS=linux GOARCH=amd64 $(GO) build -o /dev/null ./cmd/agentsecrets/ && echo "✓ OK" || (echo "✗ FAILED"; exit 1)
	@echo -n "  macOS (amd64)... "
	@GOOS=darwin GOARCH=amd64 $(GO) build -o /dev/null ./cmd/agentsecrets/ && echo "✓ OK" || (echo "✗ FAILED"; exit 1)
	@echo -n "  Windows (amd64)... "
	@GOOS=windows GOARCH=amd64 $(GO) build -o /dev/null ./cmd/agentsecrets/ && echo "✓ OK" || (echo "✗ FAILED"; exit 1)
	@echo "✓ All platforms compile successfully!"

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