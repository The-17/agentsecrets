package commands

import (
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var forceLogout bool

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout and clear stored credentials",
	Long: `Logout from AgentSecrets.

	This will:
	1. Remove your private key from the OS keychain
	2. Clear stored tokens
	3. Clear cached workspace keys

	Note: Project bindings (.agentsecrets/project.json) are NOT removed.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !config.IsAuthenticated() {
			ui.Info("You're not logged in.")
			return nil
		}

		email := config.GetEmail()

		// Confirm unless --force
		if !forceLogout {
			var confirm bool
			err := huh.NewConfirm().
				Title(fmt.Sprintf("Logout from %s?", email)).
				Affirmative("Yes").
				Negative("No").
				Value(&confirm).
				Run()
			if err != nil || !confirm {
				ui.Info("Cancelled.")
				return nil
			}
		}

		if err := authService.Logout(); err != nil {
			ui.Error("Logout failed: " + err.Error())
			return nil
		}

		fmt.Println()
		ui.Success("Logged out successfully.")
		ui.Info("Run 'agentsecrets login' to log in again.")
		return nil
	},
}

func init() {
	logoutCmd.Flags().BoolVarP(&forceLogout, "force", "f", false, "Skip confirmation prompt")
}
