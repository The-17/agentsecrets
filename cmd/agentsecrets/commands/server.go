package commands

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var (
	serverProjectFlag bool
	serverForceFlag   bool
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Manage target AgentSecrets server (Default vs Self-Hosted)",
	Long: `View and configure the target AgentSecrets server endpoint.

	By default, AgentSecrets targets the default AgentSecrets Server endpoint.
	You can point your CLI to an open-source Self-Hosted AgentSecrets Server
	either globally or per-project.

	Examples:
	agentsecrets server get
	agentsecrets server set http://localhost:8000
	agentsecrets server set https://secrets.internal.corp/api --project
	agentsecrets server status
	agentsecrets server reset`,
	RunE: runServerGet,
}

var serverGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show current server endpoint and configuration source",
	RunE:  runServerGet,
}

var serverSetCmd = &cobra.Command{
	Use:   "set <URL>",
	Short: "Set target server endpoint (global or per-project)",
	Args:  cobra.ExactArgs(1),
	RunE:  runServerSet,
}

var serverStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check connection health and latency to active server",
	RunE:  runServerStatus,
}

var serverResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset server endpoint back to default AgentSecrets Server",
	RunE:  runServerReset,
}

func init() {
	serverSetCmd.Flags().BoolVar(&serverProjectFlag, "project", false, "Set server URL only for current project (.agentsecrets/project.json)")
	serverSetCmd.Flags().BoolVarP(&serverForceFlag, "force", "f", false, "Skip health check connectivity verification")

	serverResetCmd.Flags().BoolVar(&serverProjectFlag, "project", false, "Reset server URL only for current project")

	serverCmd.AddCommand(serverGetCmd)
	serverCmd.AddCommand(serverSetCmd)
	serverCmd.AddCommand(serverStatusCmd)
	serverCmd.AddCommand(serverResetCmd)

	rootCmd.AddCommand(serverCmd)
}

func runServerGet(cmd *cobra.Command, args []string) error {
	fmt.Println()
	ui.Banner("AgentSecrets Server Target")
	ui.Divider()

	target := config.ResolveServerTarget("")

	serverType := "AgentSecrets Server (Default)"
	if target.IsSelfHost {
		serverType = ui.BrandStyle.Render("Self-Hosted Server (Custom URL)")
	}

	ui.StatusRow("Target Type:", serverType)
	ui.StatusRow("API Endpoint:", target.URL)
	ui.StatusRow("Config Source:", target.Source)

	fmt.Println()
	if target.IsSelfHost {
		ui.Info("To reset back to default server: 'agentsecrets server reset'")
	} else {
		ui.Info("To point to a self-hosted server: 'agentsecrets server set <URL>'")
	}
	fmt.Println()
	return nil
}

func probeServerHealth(ctx context.Context, apiURL string) (bool, time.Duration, error) {
	probeURL := strings.TrimSuffix(apiURL, "/api") + "/health"
	req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
	if err != nil {
		return false, 0, err
	}

	client := &http.Client{Timeout: 3 * time.Second}
	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)
	if err != nil {
		reqAPI, err2 := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err2 == nil {
			start = time.Now()
			resp2, err3 := client.Do(reqAPI)
			duration = time.Since(start)
			if err3 == nil {
				defer resp2.Body.Close()
				return true, duration, nil
			}
		}
		return false, 0, err
	}
	defer resp.Body.Close()

	return resp.StatusCode < 500, duration, nil
}

func runServerSet(cmd *cobra.Command, args []string) error {
	rawURL := args[0]
	normURL := config.NormalizeServerURL(rawURL)

	fmt.Println()
	ui.Banner("Configure AgentSecrets Server")
	ui.Divider()

	ui.StatusRow("Target URL:", normURL)

	if !serverForceFlag {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()

		healthy, latency, err := probeServerHealth(ctx, normURL)
		if !healthy || err != nil {
			ui.Warning(fmt.Sprintf("Could not verify server connectivity at %s", normURL))
			if err != nil {
				ui.StatusRowDim("Error:", err.Error())
			}
			ui.Info("Verify that your self-hosted AgentSecrets server is running and accessible.")
			ui.Info("To save anyway without verification, run with '--force'.")
			return errors.WithSuggestions(errors.ErrConnection,
				"the server could not be verified as reachable", err,
				"run again with --force to save without verification")
		}
		ui.Success(fmt.Sprintf("Server reachable (ping: %dms)", latency.Milliseconds()))
	}

	if serverProjectFlag {
		if err := config.SetProjectServerURL(normURL); err != nil {
			return fmt.Errorf("failed to save project server URL: %w", err)
		}
		ui.Success("Saved server URL to current project config (.agentsecrets/project.json).")
	} else {
		if err := config.SetGlobalServerURL(normURL); err != nil {
			return fmt.Errorf("failed to save global server URL: %w", err)
		}
		ui.Success("Saved server URL globally (~/.agentsecrets/config.json).")
	}

	fmt.Println()
	ui.Info("Commands will now communicate with this AgentSecrets server.")
	fmt.Println()
	return nil
}

func runServerStatus(cmd *cobra.Command, args []string) error {
	fmt.Println()
	ui.Banner("Server Connection Status")
	ui.Divider()

	target := config.ResolveServerTarget("")

	serverType := "AgentSecrets Server (The Seventeen Engineering)"
	if target.IsSelfHost {
		serverType = "Self-Hosted Server (Custom URL)"
	}

	ui.StatusRow("Server Type:", serverType)
	ui.StatusRow("Endpoint:", target.URL)
	ui.StatusRow("Config Source:", target.Source)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	healthy, latency, err := probeServerHealth(ctx, target.URL)
	if err != nil || !healthy {
		ui.StatusRow("Status:", ui.ErrorStyle.Render("UNREACHABLE"))
		if err != nil {
			ui.StatusRowDim("Error:", err.Error())
		}
		fmt.Println()
		ui.Warning("Could not establish connection to the server.")
		return fmt.Errorf("server connection failed")
	}

	ui.StatusRow("Status:", ui.SuccessStyle.Render("ONLINE"))
	ui.StatusRow("Latency:", fmt.Sprintf("%dms", latency.Milliseconds()))
	fmt.Println()
	return nil
}

func runServerReset(cmd *cobra.Command, args []string) error {
	fmt.Println()
	ui.Banner("Reset Server Endpoint")
	ui.Divider()

	if serverProjectFlag {
		if err := config.SetProjectServerURL(""); err != nil {
			return fmt.Errorf("failed to reset project server URL: %w", err)
		}
		ui.Success("Project server override cleared.")
	} else {
		if err := config.ResetGlobalServerURL(); err != nil {
			return fmt.Errorf("failed to reset global server URL: %w", err)
		}
		ui.Success("Server endpoint reset to default AgentSecrets Server.")
	}

	ui.StatusRow("Active Endpoint:", config.DefaultServerURL)
	fmt.Println()
	return nil
}
