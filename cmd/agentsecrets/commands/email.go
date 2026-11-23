package commands

import (
	"fmt"
	"strconv"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/ui"
)

// emailCmd is kept as a top-level alias for the canonical `profile email`
// tree. Both trees are built by newEmailSubcommands() so they stay in sync,
// including help and flag handling.
var emailCmd = &cobra.Command{
	Use:   "email",
	Short: "Manage your account email (see: profile email)",
	Long:  "Alias for 'agentsecrets profile email'. Use the grouped command for full help.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
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

// numericCode validates the six-digit verification code shared by signup
// verification and email change.
func numericCode(s string) error {
	if s == "" {
		return fmt.Errorf("code is required")
	}
	if _, err := strconv.Atoi(s); err != nil {
		return fmt.Errorf("code must be numeric")
	}
	return nil
}

func runEmailUpdate(_ *cobra.Command, _ []string) error {
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
				Validate(numericCode),
		),
	)
	if err := otpForm.Run(); err != nil {
		return nil
	}
	otp, _ := strconv.Atoi(codeStr)

	// An OPAQUE-enrolled account keeps its credential record keyed by the
	// email. Re-enrolling under the new address also rotates the export key
	// that wraps the v2 vault share, so it has to happen together with the
	// confirm, while the old key can still be derived. Ask for the password
	// up front; it never leaves the device.
	if config.GetOpaqueEnrolled() {
		password, ok := promptReenrollPassword()
		if !ok {
			ui.Warning("Email change cancelled. Your address is unchanged.")
			return nil
		}
		if err := ui.Spinner("Confirming email change and re-linking OPAQUE...", func() error {
			return app.Auth().ChangeEmailWithOpaque(newEmail, otp, password)
		}); err != nil {
			ui.ErrorWithSuggestions(
				fmt.Errorf("email change failed: %w", err),
				"The address may already be changed. Sign in with your new email and password to finish.",
				"If that fails, use your recovery key. It is always the way back in.",
			)
			return nil
		}
		ui.Success("Email updated and OPAQUE re-linked. Sign in again with your new address.")
		return nil
	}

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
}

func runEmailVerify(_ *cobra.Command, args []string) error {
	code := ""
	if len(args) == 1 {
		code = args[0]
	}
	if code == "" {
		var entered string
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Verification code").
					Description("The six-digit code sent to " + config.GetEmail()).
					Value(&entered).
					Validate(numericCode),
			),
		)
		if err := form.Run(); err != nil {
			return nil
		}
		code = entered
	}
	otp, err := strconv.Atoi(code)
	if err != nil {
		ui.ErrorWithSuggestions(
			fmt.Errorf("invalid code: %w", err),
			"The code is six digits, as sent in the email.",
		)
		return nil
	}

	if err := ui.Spinner("Verifying email...", func() error {
		return app.Auth().VerifyEmail(otp)
	}); err != nil {
		ui.ErrorWithSuggestions(
			fmt.Errorf("email verification failed: %w", err),
			"The code may be wrong or expired. Run 'agentsecrets profile email resend' for a new one.",
		)
		return nil
	}
	ui.Success("Email verified. Cloud mode and the full feature set are unlocked.")
	return nil
}

func runEmailResend(_ *cobra.Command, _ []string) error {
	if err := ui.Spinner("Sending a new code...", func() error {
		return app.Auth().ResendVerification()
	}); err != nil {
		ui.ErrorWithSuggestions(
			fmt.Errorf("could not send a verification code: %w", err),
			"If the server reports delivery is not configured, email verification is not enabled on this host yet.",
		)
		return nil
	}
	ui.Success("A new code is on its way to " + config.GetEmail() + ".")
	return nil
}

// newEmailSubcommands builds a fresh set of email subcommands. Cobra allows a
// single parent per command, so the top-level and grouped trees each get their
// own objects while sharing the same RunE implementations above.
func newEmailSubcommands() []*cobra.Command {
	return []*cobra.Command{
		{
			Use:   "update",
			Short: "Change your account email (verification required)",
			RunE:  runEmailUpdate,
		},
		{
			Use:   "verify [code]",
			Short: "Verify your email address with the code we sent",
			Long: `Verify your email address with the six-digit code from signup.

Verification unlocks cloud mode and lifts the limits on projects and secrets.
Without it, an account still works locally, but the server refuses the
actions that need a trusted address.`,
			Args: cobra.MaximumNArgs(1),
			RunE: runEmailVerify,
		},
		{
			Use:   "resend",
			Short: "Send a fresh verification code",
			RunE:  runEmailResend,
		},
	}
}

func init() {
	emailCmd.AddCommand(newEmailSubcommands()...)
	profileEmailCmd.AddCommand(newEmailSubcommands()...)
}
