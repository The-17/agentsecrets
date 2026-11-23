package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "View and manage your account",
	Long: `View your account card and manage account-wide settings.

Examples:
  agentsecrets profile                  show the account card
  agentsecrets profile update           change your display name
  agentsecrets profile email update     change your email address
  agentsecrets profile email verify     verify your email
  agentsecrets profile email resend     send a fresh verification code
  agentsecrets profile avatar <file>    set your profile photo
  agentsecrets profile deactivate       sign out everywhere and stop logins
  agentsecrets profile delete           permanently delete the account`,
	RunE: func(cmd *cobra.Command, args []string) error {
		email := config.GetEmail()
		if email == "" {
			ui.Error("not logged in; run 'agentsecrets login' first")
			return nil
		}

		host := config.GetServerURL()
		if host == "" {
			host = "(unknown host)"
		}

		// Key fingerprint is an audit anchor: sha256 of the account public key.
		fingerprint := "(no key in store)"
		if pub, err := keyring.GetPublicKey(email); err == nil && len(pub) > 0 {
			h := sha256.Sum256(pub)
			hexed := hex.EncodeToString(h[:])
			fingerprint = "sha256:" + hexed[:8] + ".." + hexed[len(hexed)-4:]
		}

		vs, err := app.Auth().VaultStatus()
		if err != nil {
			ui.Error(fmt.Sprintf("could not read vault status: %s", err))
			return nil
		}

		var vaultLine string
		switch {
		case !vs.Supported:
			vaultLine = "not supported on this server"
		case vs.Version == 0 || len(vs.Envelopes) == 0:
			vaultLine = "no vault yet"
		default:
			vaultLine = fmt.Sprintf("v%d | %s", vs.Version, strings.Join(vs.Envelopes, ", "))
		}
		recoveryLine := "not confirmed"
		if vs.Confirmed {
			recoveryLine = "confirmed"
		}

		printAccountCard(email, host, fingerprint, vaultLine, recoveryLine)
		return nil
	},
}

// printAccountCard draws a lean ASCII card. It intentionally shows only account
// facts (identity, vault, key) and never duplicates the system-health output of
// the status command.
func printAccountCard(email, host, fingerprint, vaultLine, recoveryLine string) {
	rows := []struct{ label, value string }{
		{"email", email},
		{"host", host},
		{"key", fingerprint},
		{"vault", vaultLine},
		{"recovery key", recoveryLine},
	}

	labelWidth := 0
	valueWidth := 0
	for _, r := range rows {
		if len(r.label) > labelWidth {
			labelWidth = len(r.label)
		}
		if len(r.value) > valueWidth {
			valueWidth = len(r.value)
		}
	}

	contentWidth := labelWidth + 2 + valueWidth
	rule := strings.Repeat("─", contentWidth+2)

	fmt.Println("┌" + rule + "┐")
	for _, r := range rows {
		fmt.Printf("│ %-*s  %-*s │\n", labelWidth, r.label, valueWidth, r.value)
	}
	fmt.Println("└" + rule + "┘")
}

func init() {
	profileCmd.AddCommand(
		profileEmailCmd,
		profilePasswordCmd,
		profileReactivateCmd,
		profileUpdateCmd,
		profileAvatarCmd,
		profileDeactivateCmd,
		profileDeleteCmd,
	)
	// The account email flow lives under `profile email`; its subcommands are
	// attached in email.go. `email` remains a top-level alias in root.go.
}

var profileEmailCmd = &cobra.Command{
	Use:   "email",
	Short: "Manage your email address",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var profilePasswordCmd = &cobra.Command{
	Use:   "password",
	Short: "Manage your account password",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var profileUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Change your display name",
	RunE: func(cmd *cobra.Command, args []string) error {
		var first, last string
		form := huh.NewForm(huh.NewGroup(
			huh.NewInput().Title("First name").Value(&first).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("first name is required")
					}
					return nil
				}),
			huh.NewInput().Title("Last name").Value(&last).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("last name is required")
					}
					return nil
				}),
		))
		if err := form.Run(); err != nil {
			return nil
		}
		if err := ui.Spinner("Saving profile...", func() error {
			return app.Auth().UpdateProfile(strings.TrimSpace(first), strings.TrimSpace(last))
		}); err != nil {
			ui.Error(err.Error())
			return nil
		}
		ui.Success("Profile updated.")
		return nil
	},
}

var profileAvatarCmd = &cobra.Command{
	Use:   "avatar <file>",
	Short: "Set your profile photo (PNG, JPEG or WebP, up to 2 MB)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ui.Spinner("Uploading avatar...", func() error {
			return app.Auth().UploadAvatar(args[0])
		}); err != nil {
			ui.Error(err.Error())
			return nil
		}
		ui.Success("Profile photo updated.")
		return nil
	},
}

var profileDeactivateCmd = &cobra.Command{
	Use:   "deactivate",
	Short: "Sign out everywhere and stop new logins",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Same local password re-auth gate the other sensitive ops use. Password
		// is typed, never piped or passed as an argument.
		if err := verifyPasswordLocally(); err != nil {
			ui.Error(err.Error())
			return nil
		}

		// Establish the reactivation path before asking for the irreversible
		// step: deactivation is reversible, but NOT by logging in. A deactivated
		// account is refused on every login path. Reactivation needs a code
		// emailed to the account address. The user must know that first.
		fmt.Println()
		fmt.Println("  Deactivating signs you out of every device and blocks new logins.")
		fmt.Println("  Nothing is deleted: your workspaces, secrets, and vault stay intact.")
		fmt.Println("  Logging in will NOT reactivate the account. To reactivate, run")
		fmt.Println("  'agentsecrets profile reactivate' (or use the website) and enter the")
		fmt.Println("  code we email to your account address.")
		fmt.Println()

		var confirmed bool
		form := huh.NewForm(huh.NewGroup(
			huh.NewConfirm().
				Title("Deactivate your account?").
				Description("Login is blocked until you reactivate with an emailed code. No data is removed.").
				Value(&confirmed),
		))
		if err := form.Run(); err != nil || !confirmed {
			ui.Warning("Cancelled. Your account is unchanged.")
			return nil
		}
		if err := app.Auth().DeactivateAccount(); err != nil {
			return err
		}
		ui.Success("Account deactivated. Run 'agentsecrets profile reactivate' with the emailed code to restore login.")
		if err := config.ClearSession(); err != nil {
			return fmt.Errorf("account deactivated but session could not be cleared: %w", err)
		}
		return nil
	},
}

var profileReactivateCmd = &cobra.Command{
	Use:   "reactivate",
	Short: "Reactivate a deactivated account with an emailed code",
	Long: `Reactivate an account that was deactivated.

Deactivation blocks every login path. This command emails a one-time code to
the account address and uses it to restore login. It works while signed out.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		email := config.GetEmail()
		if email == "" {
			var entered string
			form := huh.NewForm(huh.NewGroup(
				huh.NewInput().
					Title("Account email").
					Description("The address of the deactivated account.").
					Value(&entered).
					Validate(func(s string) error {
						if !strings.Contains(s, "@") {
							return fmt.Errorf("enter a valid email")
						}
						return nil
					}),
			))
			if err := form.Run(); err != nil {
				return nil
			}
			email = strings.TrimSpace(entered)
		}

		if err := ui.Spinner("Sending reactivation code...", func() error {
			return app.Auth().RequestReactivation(email)
		}); err != nil {
			ui.Error(err.Error())
			return nil
		}
		ui.Success("If that account is deactivated, a code is on its way.")

		var codeStr string
		form := huh.NewForm(huh.NewGroup(
			huh.NewInput().
				Title("Reactivation code").
				Description("The six-digit code sent to " + email).
				Value(&codeStr).
				Validate(numericCode),
		))
		if err := form.Run(); err != nil {
			return nil
		}
		otp, err := strconv.Atoi(codeStr)
		if err != nil {
			ui.Error("Code must be six digits.")
			return nil
		}
		if err := ui.Spinner("Reactivating account...", func() error {
			return app.Auth().ConfirmReactivation(email, otp)
		}); err != nil {
			ui.Error(err.Error())
			return nil
		}
		ui.Success("Account reactivated. Sign in again with 'agentsecrets login'.")
		return nil
	},
}

var profileDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Permanently delete your account and all its data",
	RunE: func(cmd *cobra.Command, args []string) error {
		email := config.GetEmail()
		if email == "" {
			ui.Error("not logged in; run 'agentsecrets login' first")
			return nil
		}

		// Deletion is the most destructive action in the CLI. Require the same
		// local password re-auth as allowlist and other sensitive ops, before
		// showing the consequences or asking for the typed-email confirmation.
		if err := verifyPasswordLocally(); err != nil {
			ui.Error(err.Error())
			return nil
		}

		// Only after the correct password, spell out what is lost so the user
		// confirms with full knowledge of the consequences.
		fmt.Println()
		fmt.Println("  This PERMANENTLY deletes your account and everything in it:")
		fmt.Println("   - all workspaces, projects, environments, and secrets")
		fmt.Println("   - your vault, keys, agents, tokens, and activity history")
		fmt.Println("   - your recovery key; this cannot be undone or recovered")
		fmt.Println()

		var typed string
		form := huh.NewForm(huh.NewGroup(
			huh.NewInput().
				Title("Type your email to confirm permanent deletion").
				Description("This cannot be undone. Your account and all its data will be erased.").
				Value(&typed).
				Validate(func(s string) error {
					if strings.EqualFold(strings.TrimSpace(s), email) {
						return nil
					}
					return fmt.Errorf("email does not match %s", email)
				}),
		))
		if err := form.Run(); err != nil {
			return nil
		}
		if err := app.Auth().DeleteAccount(strings.TrimSpace(typed)); err != nil {
			return err
		}
		ui.Success("Account deleted.")
		if err := config.ClearSession(); err != nil {
			return fmt.Errorf("account deleted but session could not be cleared: %w", err)
		}
		return nil
	},
}
