package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keychainauth"
	agentmcp "github.com/The-17/agentsecrets/pkg/mcp"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp [verb] [json-args]",
	Short: "MCP server and machine-readable interface for AI agent integration",
	Long: `Connect AI clients to AgentSecrets over the Model Context Protocol.

	` + mcpBridgePackage + ` is the published bridge (npx). This binary also
	speaks MCP itself via "mcp serve".

	Without a subcommand, this command is the machine-readable JSON interface
	the bridge calls: one privileged local operation, one JSON envelope on
	stdout. Verbs:

	  ping, status, auth.export,
	  secrets.list, secrets.set, secrets.delete, secrets.pull, secrets.push, secrets.diff,
	  secrets.rotate, secrets.rotation_status,
	  proxy.call, proxy.status,
	  project.list, project.create, project.use, project.update, project.delete,
	  workspace.list, workspace.create, workspace.switch, workspace.members,
	  agent.list, agent.delete, agent.token_issue, agent.token_rotate,
	  logs.list, logs.summary, logs.detail

	Args are a single JSON object (argv or stdin). Stdout is always exactly one
	envelope: {"ok":true,"data":...} or {"ok":false,"error":"..."}.

	Mutating verbs are refused unless a human set AGENTSECRETS_MCP_ALLOW_WRITES=true
	in the MCP client configuration. An agent cannot enable them itself.`,
	Args: cobra.ArbitraryArgs,
	RunE: runMCPBridge,
}

// mcpBridgePackage is the published TypeScript MCP bridge. Client config names
// the package, never a version and never an absolute binary path, so a user
// upgrades by restarting their AI tool.
const mcpBridgePackage = "@the-17/agentsecrets-mcp"

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server on stdio",
	Long: `Start the MCP server using stdio transport. This is designed to be launched by
	AI clients like Claude Desktop, Cursor, or Windsurf.

	Instead of configuring this manually, run:
	agentsecrets mcp install

	AI clients start the server from their own working directory, which is
	usually NOT your repo — so by default the server cannot find your project.
	Pass --project-dir (or set AGENTSECRETS_PROJECT_DIR) to pin it:`,
	RunE: runMCPServe,
}

var mcpProjectDir string

var mcpInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Auto-configure Claude Desktop, Cursor, and OpenClaw to use AgentSecrets",
	Long: `Automatically detect Claude Desktop, Cursor, and OpenClaw installations and
	configure them to use AgentSecrets.

	By default the MCP entry runs the published bridge through npx:

	  "command": "npx",
	  "args": ["-y", "` + mcpBridgePackage + `@latest"]

	That entry carries no version pin and no absolute path, so a new release
	needs no config edit. Use --local to run this binary's "mcp serve" instead,
	for machines without Node.

	For OpenClaw, this installs the AgentSecrets skill into your skills directory.

	Supported AI tools:
	- Claude Desktop (macOS, Windows, Linux)
	- Cursor
	- OpenClaw`,
	RunE: runMCPInstall,
}

func init() {
	mcpServeCmd.Flags().StringVar(&mcpProjectDir, "project-dir", "", "Project directory holding .agentsecrets/project.json (AI clients launch from their own cwd; without this the server cannot find your project)")
	mcpCmd.AddCommand(mcpServeCmd)
	mcpCmd.AddCommand(mcpInstallCmd)
	mcpInstallCmd.Flags().Bool("local", false, "Run this binary's `mcp serve` instead of the published npx bridge")
}

// Deprecated: the bridge used to be its own subcommand at "mcp bridge <verb>".
// It is now the parent command's default action, so the supported spelling is
// "agentsecrets mcp <verb>". Kept only so old client configs keep working;
// remove after the next major version.

func runMCPServe(cmd *cobra.Command, args []string) error {
	// Pin project resolution before anything reads config: the client's cwd
	// is not our repo. Flag beats AGENTSECRETS_PROJECT_DIR beats cwd walk.
	if mcpProjectDir != "" {
		if err := config.SetProjectDirOverride(mcpProjectDir); err != nil {
			return err
		}
	}
	// Connect to the keychain-auth daemon to resolve local OS keychain secrets
	if err := keychainauth.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: keychain-auth initialization failed: %v\n", err)
	}

	// MCP uses stdio — only JSON-RPC messages should go to stdout.
	// Share the CLI-initialized services with the MCP server to avoid
	// code/state duplication (DRY).
	deps := agentmcp.Deps{
		API:        app.API(),
		Workspaces: app.Workspaces(),
		Secrets:    app.Secrets(),
	}
	if err := agentmcp.Serve(Version, deps); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		return err
	}
	return nil
}

// mcpServerEntry returns the mcpServers entry for the AgentSecrets server.
// By default it runs the published bridge through npx, so client config holds
// neither a version pin nor an absolute path. With useLocal it runs this
// binary's `mcp serve` instead, for machines without Node.
func mcpServerEntry(useLocal bool) (map[string]interface{}, error) {
	if !useLocal {
		return map[string]interface{}{
			"command": "npx",
			"args":    []string{"-y", mcpBridgePackage + "@latest"},
		}, nil
	}

	binPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("could not determine binary path: %w", err)
	}
	binPath, err = filepath.EvalSymlinks(binPath)
	if err != nil {
		return nil, fmt.Errorf("could not resolve binary path: %w", err)
	}
	return map[string]interface{}{
		"command": binPath,
		"args":    []string{"mcp", "serve"},
	}, nil
}

func runMCPInstall(cmd *cobra.Command, args []string) error {
	useLocal, _ := cmd.Flags().GetBool("local")

	entry, err := mcpServerEntry(useLocal)
	if err != nil {
		return err
	}
	if projRoot, err := config.GetProjectRoot(); err == nil && projRoot != "" {
		entry["env"] = map[string]string{config.ProjectDirEnv: projRoot}
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
		if err := installOpenClawSkill(oclawPath); err != nil {
			ui.Warning(fmt.Sprintf("OpenClaw: %v", err))
		} else {
			ui.Success("Installed OpenClaw skill")
			installed++
		}
	}

	// Try Claude Code and Codex skills directories. Both use the standard
	// SKILL.md layout, so both install from the one shared source.
	for _, c := range []struct {
		name string
		path string
	}{
		{"Claude Code", claudeCodeSkillsPath()},
		{"Codex", codexSkillsPath()},
	} {
		if c.path == "" {
			continue
		}
		if err := installSkillFiles(c.path); err != nil {
			ui.Warning(fmt.Sprintf("%s: %v", c.name, err))
		} else {
			ui.Success(fmt.Sprintf("Installed %s skill", c.name))
			installed++
		}
	}

	if installed == 0 {
		ui.Warning("No supported AI tools detected (Claude Desktop, Cursor, OpenClaw, Claude Code, Codex).")
		ui.Info("Add this to your MCP client config:")
		pretty, _ := json.MarshalIndent(map[string]interface{}{
			"mcpServers": map[string]interface{}{"agentsecrets": entry},
		}, "", "  ")
		fmt.Printf("\n%s\n\n", pretty)
		return nil
	}

	fmt.Println()
	ui.Info("Restart your AI tool to activate AgentSecrets.")
	ui.Info("Another agent? Get the same skill with: agentsecrets skill --dir <its skills directory>")
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

// claudeCodeSkillsPath is where Claude Code discovers skills. Returned only
// when the client's directory exists, so install output never claims a client
// that is not present.
func claudeCodeSkillsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	dir := filepath.Join(home, ".claude", "skills")
	if _, err := os.Stat(filepath.Dir(dir)); os.IsNotExist(err) {
		return ""
	}
	return dir
}

// codexSkillsPath is where Codex CLI discovers skills.
func codexSkillsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	dir := filepath.Join(home, ".codex", "skills")
	if _, err := os.Stat(filepath.Dir(dir)); os.IsNotExist(err) {
		return ""
	}
	return dir
}

// installOpenClawSkill writes the AgentSecrets skill files into the OpenClaw skills directory.
func installOpenClawSkill(skillsDir string) error {
	skillDir := filepath.Join(skillsDir, "agentsecrets")
	scriptsDir := filepath.Join(skillDir, "scripts")
	if err := os.MkdirAll(scriptsDir, 0755); err != nil {
		return fmt.Errorf("could not create skill directory: %w", err)
	}

	// Write SKILL.md from the one shared source, so `init` and `mcp install`
	// ship the same procedure. See skill_content.go.
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(InstalledSkill()), 0644); err != nil {
		return fmt.Errorf("failed to write SKILL.md: %w", err)
	}

	// The references are part of the skill, not an extra: OpenClaw gets them
	// too so every client sees the same depth.
	refDir := filepath.Join(skillDir, "references")
	if err := os.MkdirAll(refDir, 0755); err != nil {
		return fmt.Errorf("could not create references directory: %w", err)
	}
	for name, content := range SkillReferences() {
		if err := os.WriteFile(filepath.Join(refDir, name), []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write references/%s: %w", name, err)
		}
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

// installSkillFiles writes the standard skill into any client's skills
// directory: SKILL.md from the one shared source (skill_content.go) plus the
// references/ files. OpenClaw additionally gets helper scripts via
// installOpenClawSkill. Clients whose skill format differs from this layout
// are added here, not by forking the content.
func installSkillFiles(skillsDir string) error {
	skillDir := filepath.Join(skillsDir, "agentsecrets")
	refDir := filepath.Join(skillDir, "references")
	if err := os.MkdirAll(refDir, 0755); err != nil {
		return fmt.Errorf("could not create skill directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(InstalledSkill()), 0644); err != nil {
		return fmt.Errorf("failed to write SKILL.md: %w", err)
	}
	for name, content := range SkillReferences() {
		if err := os.WriteFile(filepath.Join(refDir, name), []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write references/%s: %w", name, err)
		}
	}
	return nil
}
