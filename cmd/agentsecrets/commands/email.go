package commands

import (
	"fmt"
	"strconv"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/ui"
)

var emailCmd = &cobra.Command{
	Use:   "email",
	Short: "Manage your account email",
}

var emailUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Change your account email (verification required)",
	RunE: func(cmd *cobra.Command, args []string) error {
		var newEmail string
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("New email").
					Description("A verification code will be sent to this address.").
					Value(&newEmail).
					Validate(func(s string) error {
						if s == "" {
							return fmt.Errorf("email is required")
						}
						return nil
					}),
			),
		)
		if err := form.Run(); err != nil {
			return nil
		}

		if err := ui.Spinner("Requesting email change...", func() error {
			return app.Auth().UpdateEmail(newEmail)
		}); err != nil {
			ui.ErrorWithSuggestions(
				fmt.Errorf("email change request failed: %w", err),
				"Make sure the new address is not already registered.",
				"If the server reports delivery is not configured, email change is not enabled on this host yet.",
			)
			return nil
		}

		ui.Success("Verification code sent. Check your new address.")

		var codeStr string
		otpForm := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Verification code").
					Description("Enter the code sent to " + newEmail).
					Value(&codeStr).
					Validate(func(s string) error {
						if s == "" {
							return fmt.Errorf("code is required")
						}
						if _, err := strconv.Atoi(s); err != nil {
							return fmt.Errorf("code must be numeric")
						}
						return nil
					}),
			),
		)
		if err := otpForm.Run(); err != nil {
			return nil
		}
		otp, _ := strconv.Atoi(codeStr)

		if err := ui.Spinner("Confirming email change...", func() error {
			return app.Auth().ConfirmEmail(newEmail, otp)
		}); err != nil {
			ui.ErrorWithSuggestions(
				fmt.Errorf("email change confirmation failed: %w", err),
				"The code may be invalid, expired, or the change was never requested.",
			)
			return nil
		}

		ui.Success("Email updated. Log in again to pick up the new address on this device.")
		return nil
	},
}

func init() {
	emailCmd.AddCommand(emailUpdateCmd)
}
