package commands

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/The-17/agentsecrets/pkg/vault"
)

var loginServerFlag string
var loginRecoveryFlag bool

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to your AgentSecrets account",
	Long: `Login to your existing AgentSecrets account.

	This will:
	1. Prompt for your email and password
	2. Authenticate with the server
	3. Decrypt your private key using your password
	4. Download and decrypt your workspace keys
	5. Cache credentials locally for future commands

	Use --recovery when you have lost the password. The recovery key unlocks
	your vault locally, proves possession to the server, and sets a new
	password. The recovery key itself is never sent to the server.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if loginServerFlag != "" {
			if err := config.SetGlobalServerURL(loginServerFlag); err != nil {
				return fmt.Errorf("invalid server URL: %w", err)
			}
		}
		if loginRecoveryFlag {
			return performRecovery()
		}
		return performLogin()
	},
}

func init() {
	loginCmd.Flags().StringVar(&loginServerFlag, "server", "", "Target AgentSecrets server URL")
	loginCmd.Flags().BoolVar(&loginRecoveryFlag, "recovery", false, "Sign in with your recovery key and set a new password")
}

// performLogin collects credentials and logs in. Shared by login command and init flow.
func performLogin() error {
	var (
		email    string
		password string
	)

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Email").
				Value(&email).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("email is required")
					}
					return nil
				}),

			huh.NewInput().
				Title("Password").
				EchoMode(huh.EchoModePassword).
				Value(&password).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("password is required")
					}
					return nil
				}),
		),
	)

	if err := form.Run(); err != nil {
		return nil
	}

	fmt.Println()

	var result *auth.LoginResult
	if err := ui.Spinner("Logging in...", func() error {
		var err error
		result, err = app.Auth().PerformLogin(email, password, nil, nil)
		return err
	}); err != nil {
		ui.ErrorWithSuggestions(
			fmt.Errorf("Login failed: %w", err),
			"Double check your email spelling and password.",
			"If you don't have an account, run 'agentsecrets init' to sign up.",
			"Verify that the AgentSecrets API endpoint is accessible from your network.",
		)
		return nil
	}

	fmt.Println()
	ui.Success("Logged in successfully!")
	justConfirmed := showVaultResult(result, password)
	enrollOpaqueAfterLogin(email, password, result, justConfirmed)
	return nil
}

// enrollOpaqueAfterLogin upgrades an account to OPAQUE once the vault exists
// and the recovery key has been confirmed, either just now or on a previous
// device.
//
// Two hard gates. Enrollment removes the password factor, so it must never run
// before recovery works, or a lost recovery key strands the account. And it must
// never run for an account already on OPAQUE, or every login would rotate the
// server's registration record. Every failure is a warning: the account keeps
// working on its password.
func enrollOpaqueAfterLogin(email, password string, result *auth.LoginResult, justConfirmed bool) {
	if result == nil || result.OpaqueLogin {
		return
	}
	if !result.RecoveryConfirmed && !justConfirmed {
		return
	}
	caps, err := app.Auth().FetchCapabilities()
	if err != nil || !caps.Opaque {
		return
	}

	if err := ui.Spinner("Enabling passwordless login (OPAQUE)...", func() error {
		return app.Auth().EnrollOpaque(email, password)
	}); err != nil {
		ui.Warning(fmt.Sprintf("Passwordless login was not enabled: %v", err))
		ui.Info("Your password login still works. Nothing changed for this account.")
		return
	}
	ui.Success("Passwordless login enabled. This account no longer uses a password on the server.")
}

// performRecovery restores a session with the recovery key, then rewraps the
// vault under a new password. The recovery key stays on the client.
func performRecovery() error {
	var (
		email       string
		recoveryKey string
		newPassword string
		confirm     string
	)

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Email").
				Value(&email).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("email is required")
					}
					return nil
				}),

			huh.NewInput().
				Title("Recovery key").
				Description("Shown once when your vault was created. Checked locally, never sent to the server.").
				EchoMode(huh.EchoModePassword).
				Value(&recoveryKey).
				Validate(func(s string) error {
					if _, err := vault.DecodeRecoveryKey(strings.TrimSpace(s)); err != nil {
						return fmt.Errorf("that does not look like a recovery key")
					}
					return nil
				}),
		),

		huh.NewGroup(
			huh.NewInput().
				Title("New password").
				Description("At least 8 characters. This replaces the forgotten password.").
				EchoMode(huh.EchoModePassword).
				Value(&newPassword).
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
					if s != newPassword {
						return fmt.Errorf("passwords do not match")
					}
					return nil
				}),
		),
	)

	if err := form.Run(); err != nil {
		return nil
	}

	fmt.Println()

	var result *auth.LoginResult
	if err := ui.Spinner("Recovering account...", func() error {
		var err error
		result, err = app.Auth().RecoverAccount(
			strings.TrimSpace(email),
			strings.TrimSpace(recoveryKey),
			newPassword,
		)
		return err
	}); err != nil {
		ui.ErrorWithSuggestions(
			fmt.Errorf("Recovery failed: %w", err),
			"Recovery keys are case-insensitive; check for missing or extra characters.",
			"Use the recovery key for the account that owns this email.",
			"Accounts created before v4 have no vault; sign in with your password once to migrate.",
		)
		return nil
	}

	fmt.Println()
	ui.Success("Account recovered. Your new password is active.")
	showVaultResult(result, newPassword)
	// Recovery proves the recovery key works, so the enrollment precondition is
	// already satisfied even though no new key was displayed. The server clears
	// the old OPAQUE record during recovery, so this re-enrolls with the new
	// password instead of leaving the account on a record it can no longer match.
	enrollOpaqueAfterLogin(strings.TrimSpace(email), newPassword, result, true)
	return nil
}
