package commands

import (
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var forceReinit bool

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize AgentSecrets and create or connect your account",
	Long: `Initialize AgentSecrets for your account and local environment.

	This sets up the configuration directory and prompts you to create a
	new account or connect an existing one.

	What happens:
	1. Creates ~/.agentsecrets/ (global config)
	2. Creates .agentsecrets/ (project config in current directory)
	3. Prompts to create account or login
	4. Generates encryption keypair (for new accounts)
	5. Stores credentials securely`,
	RunE: runInit,
}

func init() {
	initCmd.Flags().BoolVarP(&forceReinit, "force", "f", false, "Skip reinitialize confirmation")
}

func runInit(cmd *cobra.Command, args []string) error {
	// 1. Check if already initialized
	alreadyInitialized := config.GlobalConfigExists()

	if alreadyInitialized {
		ui.Warning("AgentSecrets is already initialized.")

		if !forceReinit {
			var confirm bool
			err := huh.NewConfirm().
				Title("Reinitialize?").
				Description("This will reset your config files.").
				Affirmative("Yes").
				Negative("No").
				Value(&confirm).
				Run()
			if err != nil || !confirm {
				ui.Info("Keeping existing configuration.")
				return nil
			}
		}

		// Clear existing config before re-initializing
		if err := config.ClearSession(); err != nil {
			return fmt.Errorf("failed to clear session: %w", err)
		}
		if err := config.ClearProjectConfig(); err != nil {
			return fmt.Errorf("failed to clear project config: %w", err)
		}

		fmt.Println()
	}

	// Create config directories and files
	if err := config.InitGlobalConfig(); err != nil {
		return fmt.Errorf("failed to initialize global config: %w", err)
	}
	if err := config.InitProjectConfig(); err != nil {
		return fmt.Errorf("failed to initialize project config: %w", err)
	}

	ui.Banner("⚡ AgentSecrets")
	fmt.Println()

	// 2. Ask: Create account or Login
	var choice string
	err := huh.NewSelect[string]().
		Title("What would you like to do?").
		Options(
			huh.NewOption("Create a new account", "signup"),
			huh.NewOption("Login to existing account", "login"),
		).
		Value(&choice).
		Run()
	if err != nil {
		return nil
	}

	fmt.Println()

	switch choice {
	case "signup":
		return runSignup()
	case "login":
		return runLoginFlow()
	default:
		return nil
	}
}

func runSignup() error {
	var (
		firstName string
		lastName  string
		email     string
		password  string
	)

	// Collect signup info with styled form
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("First name").
				Value(&firstName).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("first name is required")
					}
					return nil
				}),

			huh.NewInput().
				Title("Last name").
				Value(&lastName).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("last name is required")
					}
					return nil
				}),

			huh.NewInput().
				Title("Email").
				Value(&email).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("email is required")
					}
					return nil
				}),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("Password").
				Description("Minimum 8 characters").
				EchoMode(huh.EchoModePassword).
				Value(&password).
				Validate(func(s string) error {
					if len(s) < 8 {
						return fmt.Errorf("password must be at least 8 characters")
					}
					return nil
				}),

			huh.NewInput().
				Title("Confirm password").
				EchoMode(huh.EchoModePassword).
				Validate(func(s string) error {
					if s != password {
						return fmt.Errorf("passwords do not match")
					}
					return nil
				}),
		),
	)

	if err := form.Run(); err != nil {
		return nil // User cancelled
	}

	fmt.Println()

	// Create account with spinner
	if err := ui.Spinner("Creating your account...", func() error {
		return authService.Signup(auth.SignupRequest{
			FirstName: firstName,
			LastName:  lastName,
			Email:     email,
			Password:  password,
		})
	}); err != nil {
		ui.Error("Signup failed: " + err.Error())
		return nil
	}

	fmt.Println()
	ui.Success("Account created and logged in!")
	ui.Info("Run 'agentsecrets status' to see your session info.")
	return nil
}

func runLoginFlow() error {
	return performLogin()
}
