#!/bin/bash

# Isolated Development Environment for AgentSecrets
# This script sets up and enters a sandboxed environment for developing/testing.

# Get current script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="$HOME/.agentsecrets-dev"

mkdir -p "$SANDBOX_DIR/go/bin"

# 2. Compile current agentsecrets binary
echo "Building local agentsecrets..."
(cd "$SCRIPT_DIR" && go build -o bin/agentsecrets ./cmd/agentsecrets/)
echo "✓ agentsecrets binary built: $SCRIPT_DIR/bin/agentsecrets"

# 3. Spawn isolated shell session
echo ""
echo "Entering isolated development session. Type 'exit' to return."
echo "Sandbox path: $SANDBOX_DIR"
echo "--------------------------------------------------------"

env HOME="$SANDBOX_DIR" \
    XDG_CONFIG_HOME="" \
    XDG_DATA_HOME="" \
    XDG_RUNTIME_DIR="" \
    bash --rcfile <(echo '
        export PS1="\[\e[36m\][agentsecrets-dev]\[\e[0m\] \w \$ "
        alias agentsecrets="./bin/agentsecrets"
        alias kc-auth="$HOME/go/bin/keychain-auth"
        echo -e "\e[1;36mAgentSecrets Sandbox Session Active!\e[0m"
        echo "--------------------------------------------------------"
        echo "Your files will be written to:"
        echo " - Configs:  ~/.agentsecrets/   -> '$SANDBOX_DIR/.agentsecrets/'"
        echo " - Keyring:  ~/.keychain-auth/   -> '$SANDBOX_DIR/.keychain-auth/'"
        echo " - Socket:   ~/.cache/           -> '$SANDBOX_DIR/.cache/keychain-auth/'"
        echo "--------------------------------------------------------"
        echo "Aliases:"
        echo " - \`agentsecrets\` -> \`./bin/agentsecrets\` (locally compiled CLI)"
        echo " - \`kc-auth\`      -> \`\$HOME/go/bin/keychain-auth\` (locally compiled daemon)"
    ')
