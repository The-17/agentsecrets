package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/secrets"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var forceReinit bool
var storageMode int

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize AgentSecrets and create or connect your account",
	Long: `Initialize AgentSecrets for your account and local environment.

	This sets up the configuration directory and prompts you to create a
	new account or connect an existing one.

	What happens:
	1. Creates ~/.agentsecrets/ (global config)
	2. Creates .agentsecrets/ (project config in current directory)
	3. Creates .agent/workflows/api-call.md (teaches AI assistants to use AgentSecrets)
	4. Prompts to create account or login
	5. Generates encryption keypair (for new accounts)
	6. Stores credentials securely`,
	RunE: runInit,
}

func init() {
	initCmd.Flags().BoolVarP(&forceReinit, "force", "f", false, "Skip reinitialize confirmation")
	initCmd.Flags().IntVar(&storageMode, "storage-mode", 1, "Set storage mode (1: keychain only, 2: keychain & .env file)")
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

	// Ask for storage mode if it wasn't explicitly passed via flag
	modeToSet := storageMode
	if !cmd.Flags().Changed("storage-mode") {
		var modeChoice string
		err := huh.NewSelect[string]().
			Title("How would you like secrets to be stored locally?").
			Options(
				huh.NewOption("1. Keychain only (recommended) — values never written to disk.\n   .env.example created with key names only.", "1"),
				huh.NewOption("2. .env file — plaintext file, compatible with all existing tooling.", "2"),
			).
			Value(&modeChoice).
			Run()
		
		if err == nil {
			if modeChoice == "2" {
				modeToSet = 2
			} else {
				modeToSet = 1
			}
		}
	}

	// Set storage mode in global config.
	if err := config.SetStorageMode(modeToSet); err != nil {
		return fmt.Errorf("failed to set storage mode: %w", err)
	}

	// Create blank .env files based on storage mode footprint to ensure they exist immediately
	secretsEnv := secrets.NewEnvManager()
	_ = secretsEnv.Write(make(map[string]string))

	_ = writeWorkflowFile()

	ui.Banner("AgentSecrets")
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

const workflowContent = `---
description: Make authenticated API calls using AgentSecrets (never exposes secrets)
---

When the user asks you to make an API call that requires authentication, use AgentSecrets.
Credentials are resolved from the OS keychain — you will NEVER see the actual secret values.

1. List available secret keys:
// turbo
` + "```" + `bash
agentsecrets secrets list
` + "```" + `

2. Make the authenticated call:
` + "```" + `bash
agentsecrets call --url <URL> --method <METHOD> --bearer <KEY_NAME>
` + "```" + `

   Other auth styles:
   - ` + "`" + `--header HeaderName=KEY_NAME` + "`" + ` (custom header)
   - ` + "`" + `--query param=KEY_NAME` + "`" + ` (query parameter)
   - ` + "`" + `--basic KEY_NAME` + "`" + ` (basic auth)
   - ` + "`" + `--body-field json.path=KEY_NAME` + "`" + ` (JSON body path)
   - ` + "`" + `--form-field field=KEY_NAME` + "`" + ` (form field)

   POST example:
` + "```" + `bash
agentsecrets call --url https://api.stripe.com/v1/charges \
  --method POST --bearer STRIPE_KEY \
  --body '{"amount":1000,"currency":"usd"}'
` + "```" + `

3. NEVER ask the user for actual secret values. Use key names from step 1 only.
4. If a key is missing, tell the user to run: agentsecrets secrets set KEY_NAME=value
`

func writeWorkflowFile() error {
	dir := filepath.Join(".", ".agent", "workflows")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "api-call.md"), []byte(workflowContent), 0644)
}

