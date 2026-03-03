package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	agentmcp "github.com/The-17/agentsecrets/pkg/mcp"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "MCP server for AI agent integration",
	Long:  `Start an MCP (Model Context Protocol) server that exposes api_call and list_secrets tools for AI agents like Claude, Cursor, and Windsurf.`,
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server on stdio",
	Long: `Start the MCP server using stdio transport. This is designed to be launched by
	AI clients like Claude Desktop, Cursor, or Windsurf.

	Instead of configuring this manually, run:
	agentsecrets mcp install`,
	RunE: runMCPServe,
}

var mcpInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Auto-configure Claude Desktop, Cursor, and OpenClaw to use AgentSecrets",
	Long: `Automatically detect Claude Desktop, Cursor, and OpenClaw installations and
	configure them to use AgentSecrets.

	For Claude Desktop and Cursor, this writes MCP config so your AI tools can
	call api_call and list_secrets without any manual JSON editing.

	For OpenClaw, this installs the AgentSecrets skill into your skills directory.

	Supported AI tools:
	- Claude Desktop (macOS, Windows, Linux)
	- Cursor
	- OpenClaw`,
	RunE: runMCPInstall,
}

func init() {
	mcpCmd.AddCommand(mcpServeCmd)
	mcpCmd.AddCommand(mcpInstallCmd)
}

func runMCPServe(cmd *cobra.Command, args []string) error {
	// MCP uses stdio — only JSON-RPC messages should go to stdout.
	if err := agentmcp.Serve(); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		return err
	}
	return nil
}

func runMCPInstall(cmd *cobra.Command, args []string) error {
	// Find our own binary path
	binPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not determine binary path: %w", err)
	}
	binPath, err = filepath.EvalSymlinks(binPath)
	if err != nil {
		return fmt.Errorf("could not resolve binary path: %w", err)
	}

	// MCP entry to write
	entry := map[string]interface{}{
		"command": binPath,
		"args":    []string{"mcp", "serve"},
	}

	installed := 0

	// Try Claude Desktop
	claudePath := claudeConfigPath()
	if claudePath != "" {
		if err := writeMCPConfig(claudePath, "agentsecrets", entry); err != nil {
			ui.Warning(fmt.Sprintf("Claude Desktop: %v", err))
		} else {
			ui.Success("Configured Claude Desktop")
			installed++
		}
	}

	// Try Cursor
	cursorPath := cursorConfigPath()
	if cursorPath != "" {
		if err := writeMCPConfig(cursorPath, "agentsecrets", entry); err != nil {
			ui.Warning(fmt.Sprintf("Cursor: %v", err))
		} else {
			ui.Success("Configured Cursor")
			installed++
		}
	}

	// Try OpenClaw
	oclawPath := openclawSkillsPath()
	if oclawPath != "" {
		if err := installOpenClawSkill(oclawPath, binPath); err != nil {
			ui.Warning(fmt.Sprintf("OpenClaw: %v", err))
		} else {
			ui.Success("Configured OpenClaw (skill installed)")
			installed++
		}
	}

	if installed == 0 {
		ui.Warning("No supported AI tools detected (Claude Desktop, Cursor, OpenClaw).")
		ui.Info("You can manually add this to your MCP config:")
		fmt.Printf("\n  Binary: %s\n  Args:   mcp serve\n\n", binPath)
		return nil
	}

	fmt.Println()
	ui.Info("Restart your AI tool to activate AgentSecrets.")
	return nil
}

// writeMCPConfig reads/creates an MCP config file and adds/updates the given server entry.
func writeMCPConfig(path string, serverName string, entry map[string]interface{}) error {
	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("could not create config directory: %w", err)
	}

	// Read existing config or start fresh
	cfg := make(map[string]interface{})
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("existing config is invalid JSON: %w", err)
		}
	}

	// Get or create mcpServers map
	servers, ok := cfg["mcpServers"].(map[string]interface{})
	if !ok {
		servers = make(map[string]interface{})
	}
	servers[serverName] = entry
	cfg["mcpServers"] = servers

	// Write back with nice formatting
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

func claudeConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			return ""
		}
		return filepath.Join(appdata, "Claude", "claude_desktop_config.json")
	case "linux":
		return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
	default:
		return ""
	}
}

func cursorConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cursor", "mcp.json")
}

func openclawSkillsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	oclawDir := filepath.Join(home, ".openclaw")
	if _, err := os.Stat(oclawDir); os.IsNotExist(err) {
		return ""
	}
	return filepath.Join(oclawDir, "skills")
}

// installOpenClawSkill writes the AgentSecrets skill files into the OpenClaw skills directory.
func installOpenClawSkill(skillsDir string, binPath string) error {
	skillDir := filepath.Join(skillsDir, "agentsecrets")
	scriptsDir := filepath.Join(skillDir, "scripts")
	if err := os.MkdirAll(scriptsDir, 0755); err != nil {
		return fmt.Errorf("could not create skill directory: %w", err)
	}

	// Write SKILL.md — condensed version with guided setup workflow
	skillContent := `---
name: agentsecrets
description: Zero-knowledge credential management — make authenticated API calls without exposing your keys
version: 1.0.0
tags:
  - security
  - credentials
  - api
homepage: https://github.com/The-17/agentsecrets
metadata:
  clawdbot:
    summary: Secure credential proxy — agent makes API calls without seeing key values
    author: The Seventeen
    license: MIT
requires:
  binaries:
    - name: agentsecrets
      description: The AgentSecrets CLI binary
      install: "pip install git+https://github.com/The-17/agentsecrets#subdirectory=pypi"
files:
  - "scripts/*"
---

# AgentSecrets — Zero-Knowledge Credential Management

Make authenticated API calls without ever exposing credentials. Keys stay in the OS keychain.

## GUIDED SETUP WORKFLOW

Follow this when a user first needs API authentication.

### Step 1: Check installation
` + "```bash" + `
agentsecrets --version 2>/dev/null && echo "INSTALLED" || echo "NOT_INSTALLED"
` + "```" + `
If not installed, explain the security benefit and run: ` + "`pip install git+https://github.com/The-17/agentsecrets#subdirectory=pypi`" + `

### Step 2: Initialize
` + "```bash" + `
agentsecrets status 2>/dev/null && echo "INITIALIZED" || echo "NOT_INITIALIZED"
` + "```" + `
If not initialized, run: ` + "`agentsecrets init --skip-login`" + `

### Step 3: Collect credentials conversationally
When the user needs an API key stored, ask naturally and store IMMEDIATELY:
` + "```bash" + `
agentsecrets secrets set KEY_NAME=<value_they_gave>
` + "```" + `
Then tell them: "Stored securely as KEY_NAME. You can delete the message with the raw key."

**Naming**: STRIPE_KEY, OPENAI_KEY, GITHUB_TOKEN, GOOGLE_MAPS_KEY, etc. (uppercase, underscores)

### Step 4: Confirm readiness
List stored keys: ` + "`agentsecrets secrets list`" + `

## MAKING API CALLS

` + "```bash" + `
agentsecrets call --url <API_URL> --method <METHOD> --bearer <KEY_NAME>
` + "```" + `

### Auth Styles
| Pattern | Flag | Example |
|---------|------|---------|
| Bearer token | --bearer KEY | --bearer STRIPE_KEY |
| Custom header | --header Name=KEY | --header X-API-Key=MY_KEY |
| Query param | --query param=KEY | --query key=GMAP_KEY |
| Basic auth | --basic KEY | --basic CREDENTIALS |
| Body field | --body-field path=KEY | --body-field client_secret=SECRET |
| Form field | --form-field name=KEY | --form-field api_key=KEY |

### API Call Blocked by Zero-Trust Allowlist
If an API call returns a 403 error stating the domain is not in the workspace allowlist:
1. Do not bypass the proxy.
2. Tell the user exactly what to run in their terminal to authorize the domain:
   ` + "`agentsecrets workspace allowlist add <domain>`" + `
   *(Wait for their confirmation that they have entered their password and added the domain)*
3. Retry the API call.

## CRITICAL RULES

1. NEVER display or log actual key values after storing
2. NEVER ask for a key already stored — use the name
3. ALWAYS use agentsecrets call instead of curl
4. ALWAYS suggest deleting chat messages containing raw keys
5. If a key is missing, ask the user — don't guess
6. Respect the Zero-Trust Allowlist — if a domain is blocked, instruct the user to run ` + "`agentsecrets workspace allowlist add <domain>`" + `.

## Security & Privacy

- Zero-knowledge: agent never sees credential values after storage
- OS keychain: encrypted, system-protected
- Full audit trail: key names only, never values
- Local only: no cloud, no telemetry
`

	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(skillContent), 0644); err != nil {
		return fmt.Errorf("failed to write SKILL.md: %w", err)
	}

	// Write check-health.sh
	healthScript := "#!/usr/bin/env bash\n" +
		"set -euo pipefail\n" +
		"if ! command -v agentsecrets &>/dev/null; then\n" +
		"  echo \"ERROR: agentsecrets not installed. Run: pip install agentsecrets\"\n" +
		"  exit 1\n" +
		"fi\n" +
		"echo \"AgentSecrets is ready.\"\n" +
		"agentsecrets secrets list 2>/dev/null || echo \"(no keys set)\"\n"

	if err := os.WriteFile(filepath.Join(scriptsDir, "check-health.sh"), []byte(healthScript), 0755); err != nil {
		return fmt.Errorf("failed to write check-health.sh: %w", err)
	}

	// Write secure-call.sh — simple passthrough; agentsecrets binary handles arg parsing safely
	callScript := "#!/usr/bin/env bash\n" +
		"set -euo pipefail\n" +
		"if ! command -v agentsecrets &>/dev/null; then\n" +
		"  echo \"ERROR: agentsecrets not installed. Run: pip install agentsecrets\"\n" +
		"  exit 1\n" +
		"fi\n" +
		"exec agentsecrets call \"$@\"\n"

	if err := os.WriteFile(filepath.Join(scriptsDir, "secure-call.sh"), []byte(callScript), 0755); err != nil {
		return fmt.Errorf("failed to write secure-call.sh: %w", err)
	}

	return nil
}
