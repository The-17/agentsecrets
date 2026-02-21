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
		ui.StatusRow("Logged in:", email)

		// Workspace info
		wsID := config.GetSelectedWorkspaceID()
		if wsID != "" {
			globalConfig, err := config.LoadGlobalConfig()
			if err == nil && globalConfig.Workspaces != nil {
				if ws, ok := globalConfig.Workspaces[wsID]; ok {
					wsType := "personal"
					if ws.Type == "team" {
						wsType = "shared"
					}
					ui.StatusRow("Workspace:", fmt.Sprintf("%s (%s)", ws.Name, wsType))
				} else {
					ui.StatusRow("Workspace:", wsID)
				}
			}
		} else {
			ui.StatusRowDim("Workspace:", "—")
		}

		// Project info
		project, err := config.LoadProjectConfig()
		if err == nil && project.ProjectName != "" {
			display := project.ProjectName
			if project.WorkspaceName != "" {
				display += fmt.Sprintf(" in %s", project.WorkspaceName)
			}
			ui.StatusRow("Project:", display)
			if project.Environment != "" {
				ui.StatusRow("Environment:", project.Environment)
			}
		} else {
			ui.StatusRowDim("Project:", "—")
		}

		fmt.Println()
		return nil
	},
}
