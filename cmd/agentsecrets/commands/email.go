package commands

import (
	"fmt"
	"strconv"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
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

		// An OPAQUE-enrolled account keeps its credential record keyed by the
		// email, so re-enroll it under the new address to keep login working.
		// The password never leaves the device; only the OPAQUE record moves.
		if config.GetOpaqueEnrolled() {
			password, ok := promptReenrollPassword()
			if !ok {
				ui.Warning("Email updated, but OPAQUE was not re-linked. Run 'agentsecrets login' with your new email and password to finish the switch.")
				return nil
			}
			if _, err := app.Auth().EnrollOpaque(newEmail, password); err != nil {
				ui.Warning("Email updated, but OPAQUE re-link failed: " + err.Error() +
					". Run 'agentsecrets login' with your new email and password to finish.")
				return nil
			}
			ui.Success("Email updated and OPAQUE re-linked to your new address. Log in again to finish.")
			return nil
		}

		ui.Success("Email updated. Log in again to pick up the new address on this device.")
		return nil
	},
}

// promptReenrollPassword asks for the account password so OPAQUE can be
// re-enrolled under the new email after an address change.
func promptReenrollPassword() (string, bool) {
	var password string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Password").
				Description("Re-enter your password to re-link OPAQUE to your new email.").
				EchoMode(huh.EchoModePassword).
				Value(&password).
				Validate(func(s string) error {
					if len(s) < 8 {
						return fmt.Errorf("password must be at least 8 characters")
					}
					return nil
				}),
		),
	)
	if err := form.Run(); err != nil {
		return "", false
	}
	return password, true
}

func init() {
	emailCmd.AddCommand(emailUpdateCmd)
}
