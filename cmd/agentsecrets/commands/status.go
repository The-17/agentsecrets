package commands

import (
	"fmt"

	"github.com/spf13/cobra"

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
		if wsID != "" {
			globalConfig, err := config.LoadGlobalConfig()
			if err == nil && globalConfig.Workspaces != nil {
				if ws, ok := globalConfig.Workspaces[wsID]; ok {
					wsType := "shared"
					if ws.Type == "personal" {
						wsType = "personal"
					}
					ui.StatusRow("Selected Workspace:", fmt.Sprintf("%s (%s)", ws.Name, wsType))
				} else {
					ui.StatusRow("Selected Workspace:", wsID)
				}
			}
		} else {
			ui.StatusRowDim("Selected Workspace:", "—")
		}

		// Project info
		project, err := config.LoadProjectConfig()
		if err == nil && project.ProjectName != "" {
			projectName := project.ProjectName
			workspaceName := project.WorkspaceName
			
			// If workspace name isn't in project config, try to find it in global
			if workspaceName == "" {
				globalConfig, _ := config.LoadGlobalConfig()
				if ws, ok := globalConfig.Workspaces[project.WorkspaceID]; ok {
					workspaceName = ws.Name
				}
			}

			projectDisplay := projectName
			if workspaceName != "" {
				projectDisplay += fmt.Sprintf(" (in %s)", workspaceName)
			}
			ui.StatusRow("Current Project:", projectDisplay)

			// Sync info (Placeholders for now, will be updated in Secret Layer)
			ui.StatusRow("Secrets:", "0 synced (0 unsynced)")
			
			pushStr := "Never"
			if project.LastPush != "" {
				pushStr = project.LastPush
			}
			pullStr := "Never"
			if project.LastPull != "" {
				pullStr = project.LastPull
			}
			ui.StatusRow("Activity:", fmt.Sprintf("Last Push: %s | Last Pull: %s", pushStr, pullStr))
			
			if project.Environment != "" {
				ui.StatusRow("Environment:", project.Environment)
			}
		} else {
			ui.StatusRowDim("Current Project:", "—")
		}

		fmt.Println()
		return nil
	},
}
