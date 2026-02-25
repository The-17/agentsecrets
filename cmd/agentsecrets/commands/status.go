package commands

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/dustin/go-humanize"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current session and project info",
	Long: `Show the current AgentSecrets session status.

	Displays:
	- Whether you're logged in
	- Your email
	- Active workspace
	- Current project (if in a project directory)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println()
		ui.Banner("AgentSecrets Status")
		ui.Divider()

		// Auth status
		if !config.IsAuthenticated() {
			ui.StatusRowDim("Logged in:", "No")
			fmt.Println()
			ui.Info("  Run 'agentsecrets init' to create an account")
			ui.Info("  Run 'agentsecrets login' to log in")
			fmt.Println()
			return nil
		}

		email := config.GetEmail()
		ui.StatusRow("Logged in as:", email)

		// Workspace info
		wsID := config.GetSelectedWorkspaceID()
		global, _ := config.LoadGlobalConfig()
		
		wsDisplay := "—"
		wsDim := true
		if wsID != "" && global != nil {
			if ws, ok := global.Workspaces[wsID]; ok {
				wsDisplay = fmt.Sprintf("%s (%s)", ws.Name, ws.Type)
				wsDim = false
			} else {
				wsDisplay = wsID
				wsDim = false
			}
		}
		
		if wsDim {
			ui.StatusRowDim("Selected Workspace:", wsDisplay)
		} else {
			ui.StatusRow("Selected Workspace:", wsDisplay)
		}

		// Project info
		p, err := config.LoadProjectConfig()
		if err == nil && p.ProjectName != "" {
			workspaceName := p.WorkspaceName
			if workspaceName == "" && global != nil {
				if ws, ok := global.Workspaces[p.WorkspaceID]; ok {
					workspaceName = ws.Name
				}
			}

			projectDisplay := p.ProjectName
			if workspaceName != "" {
				projectDisplay += fmt.Sprintf(" (in %s)", workspaceName)
			}
			ui.StatusRow("Current Project:", projectDisplay)

			// Sync info
			secretsDisplay := "Unable to calculate"
			if secretsService != nil {
				diff, diffErr := secretsService.Diff()
				if diffErr != nil {
					secretsDisplay = fmt.Sprintf("Could not check (%s)", diffErr.Error())
				} else {
					syncedCount := len(diff.Unchanged)
					unsyncedCount := len(diff.Added) + len(diff.Changed) + len(diff.Removed)
					total := syncedCount + unsyncedCount
					if total == 0 {
						secretsDisplay = "No secrets found"
					} else {
						secretsDisplay = fmt.Sprintf("%d synced (%d unsynced)", syncedCount, unsyncedCount)
					}
				}
			}
			ui.StatusRow("Secrets:", secretsDisplay)
			
			ui.StatusRow("Activity:", fmt.Sprintf("Last Push: %s | Last Pull: %s", formatTime(p.LastPush), formatTime(p.LastPull)))
		} else {
			ui.StatusRowDim("Current Project:", "—")
		}

		fmt.Println()
		return nil
	},
}

func formatTime(rfc3339Str string) string {
	if rfc3339Str == "" {
		return "Never"
	}
	t, err := time.Parse(time.RFC3339, rfc3339Str)
	if err != nil {
		return rfc3339Str
	}
	return humanize.Time(t)
}
