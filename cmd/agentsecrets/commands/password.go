package commands

import (
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/ui"
)

var passwordCmd = &cobra.Command{
	Use:   "password",
	Short: "Manage your account password",
}

var passwordChangeCmd = &cobra.Command{
	Use:   "change",
	Short: "Change your account password",
	Long: `Change your account password.

The private key is re-encrypted locally with the new password. If the account
has a v4 vault, its password envelope is re-wrapped in the same request, so the
recovery key stays valid.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var current, next, confirm string

		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Current password").
					EchoMode(huh.EchoModePassword).
					Value(&current).
					Validate(func(s string) error {
						if s == "" {
							return fmt.Errorf("current password is required")
						}
						return nil
					}),
			),
			huh.NewGroup(
				huh.NewInput().
					Title("New password").
					Description("Minimum 8 characters").
					EchoMode(huh.EchoModePassword).
					Value(&next).
					Validate(func(s string) error {
						if len(s) < 8 {
							return fmt.Errorf("password must be at least 8 characters")
						}
						return nil
					}),
				huh.NewInput().
					Title("Confirm new password").
					EchoMode(huh.EchoModePassword).
					Value(&confirm).
					Validate(func(s string) error {
						if s != next {
							return fmt.Errorf("passwords do not match")
						}
						return nil
					}),
			),
		)
		if err := form.Run(); err != nil {
			return nil
		}

		if err := ui.Spinner("Changing password...", func() error {
			return app.Auth().ChangePassword(current, next)
		}); err != nil {
			ui.ErrorWithSuggestions(
				fmt.Errorf("Password change failed: %w", err),
				"Check that the current password is correct.",
				"If an old client changed the password, log in again first to repair the vault.",
			)
			return nil
		}

		ui.Success("Password changed successfully.")
		return nil
	},
}

func init() {
	passwordCmd.AddCommand(passwordChangeCmd)
}
