package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/The-17/agentsecrets/pkg/vault"
)

var loginServerFlag string
var loginRecoveryFlag bool
var loginGoogleFlag bool
var loginGithubFlag bool

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to your AgentSecrets account",
	Long: `Login to your existing AgentSecrets account.

	Run it with no flags to choose a sign-in method: email and password, Google,
	GitHub, or your recovery key. Or pass --google, --github, or --recovery to
	go straight to that method.

	An email and password login also unlocks your vault on this device. A social
	login proves your identity but does not unlock secrets; run this command
	with your password afterwards to unlock them here.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if loginServerFlag != "" {
			if err := config.SetGlobalServerURL(loginServerFlag); err != nil {
				return fmt.Errorf("invalid server URL: %w", err)
			}
		}
		if loginRecoveryFlag {
			return performRecovery()
		}
		if loginGoogleFlag && loginGithubFlag {
			return fmt.Errorf("choose one provider: --google or --github")
		}
		if loginGoogleFlag {
			return performOAuth("google")
		}
		if loginGithubFlag {
			return performOAuth("github")
		}
		// No explicit method: ask when there is a terminal, else keep the
		// historical email+password path for scripts.
		if term.IsTerminal(int(os.Stdin.Fd())) {
			return chooseLoginMethod()
		}
		return performLogin()
	},
}

func init() {
	loginCmd.Flags().StringVar(&loginServerFlag, "server", "", "Target AgentSecrets server URL")
	loginCmd.Flags().BoolVar(&loginRecoveryFlag, "recovery", false, "Sign in with your recovery key and set a new password")
	loginCmd.Flags().BoolVar(&loginGoogleFlag, "google", false, "Sign in with Google")
	loginCmd.Flags().BoolVar(&loginGithubFlag, "github", false, "Sign in with GitHub")
}

// chooseLoginMethod shows the sign-in picker and dispatches to the chosen flow.
func chooseLoginMethod() error {
	var choice string
	err := huh.NewSelect[string]().
		Title("How would you like to sign in?").
		Options(
			huh.NewOption("Email and password", "password"),
			huh.NewOption("Continue with Google", "google"),
			huh.NewOption("Continue with GitHub", "github"),
			huh.NewOption("Recovery key", "recovery"),
		).
		Value(&choice).
		Run()
	if err != nil {
		// Cancelled or no usable terminal.
		return nil
	}

	fmt.Println()
	switch choice {
	case "google":
		return performOAuth("google")
	case "github":
		return performOAuth("github")
	case "recovery":
		return performRecovery()
	default:
		return performLogin()
	}
}

// performOAuth runs the browser loopback sign-in for a provider.
func performOAuth(provider string) error {
	var result *auth.LoginResult
	label := "Google"
	if provider == "github" {
		label = "GitHub"
	}
	if err := ui.Spinner("Opening "+label+" sign-in...", func() error {
		var err error
		result, err = app.Auth().OAuthLogin(provider)
		return err
	}); err != nil {
		return errors.WithSuggestions(errors.FromError(err).Code, label+" sign-in failed", err,
			"Make sure the provider is enabled on the server (OAUTH_"+strings.ToUpper(provider)+"_ENABLED).",
			"Check that your browser opened and you completed the consent screen.",
			"Retry with 'agentsecrets login --"+provider+"'.")
	}

	fmt.Println()
	ui.Success("Signed in with " + label + "!")
	if result != nil {
		for _, warning := range result.Warnings {
			ui.Warning(warning)
		}
	}
	return nil
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
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New(errors.ErrUsage,
				"this step asks for your credentials and there is no terminal here to type them in",
				fmt.Errorf("run it in an interactive shell"))
		}
		return nil // cancelled by the user
	}

	fmt.Println()

	var result *auth.LoginResult
	if err := ui.Spinner("Logging in...", func() error {
		var err error
		result, err = app.Auth().PerformLogin(email, password, nil, nil)
		return err
	}); err != nil {
		// Keep the specific hints but fail the process. Logging in is what every
		// later command depends on, so exiting 0 here hides a dead session.
		return errors.WithSuggestions(errors.FromError(err).Code, "login failed", err,
			"Double check your email spelling and password.",
			"If you don't have an account, run 'agentsecrets init' to sign up.",
			"Verify that the AgentSecrets API endpoint is accessible from your network.")
	}

	fmt.Println()
	ui.Success("Logged in successfully!")
	showVaultResult(result, password)
	return nil
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
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New(errors.ErrUsage,
				"this step asks for your credentials and there is no terminal here to type them in",
				fmt.Errorf("run it in an interactive shell"))
		}
		return nil // cancelled by the user
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
		return errors.WithSuggestions(errors.FromError(err).Code, "recovery failed", err,
			"Recovery keys are case-insensitive; check for missing or extra characters.",
			"Use the recovery key for the account that owns this email.",
			"Accounts created before v4 have no vault; sign in with your password once to migrate.")
	}

	fmt.Println()
	ui.Success("Account recovered. Your new password is active.")
	showVaultResult(result, newPassword)
	return nil
}
