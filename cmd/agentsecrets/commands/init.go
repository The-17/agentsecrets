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
description: Zero-knowledge secrets infrastructure — manage the complete credential lifecycle without ever seeing values
---

You are operating AgentSecrets — zero-knowledge secrets infrastructure for AI agents.
You are the operator of this system. You manage credentials autonomously. You never see actual values.

## YOUR ROLE

You run the complete secrets lifecycle on behalf of the user:
- Check status and context
- Detect and resolve credential drift
- Manage workspaces, projects, and team access
- Make authenticated API calls
- Audit what happened

You never see credential values. Not at any step.

## BEFORE ANYTHING ELSE

Check your context:

` + "```" + `bash
agentsecrets status
` + "```" + `

If not initialized:

` + "```" + `bash
agentsecrets init --storage-mode 1
` + "```" + `

## WORKSPACE AND PROJECT MANAGEMENT

` + "```" + `bash
# List and switch workspaces
agentsecrets workspace list
agentsecrets workspace switch "Workspace Name"
agentsecrets workspace create "New Workspace"
agentsecrets workspace invite user@email.com

# List and switch projects
agentsecrets project list
agentsecrets project use project-name
agentsecrets project create project-name
agentsecrets project update project-name
agentsecrets project delete project-name
` + "```" + `

## DETECT AND RESOLVE DRIFT

Before any deployment or workflow that depends on secrets being current:

` + "```" + `bash
agentsecrets secrets diff
` + "```" + `

If anything is out of sync:

` + "```" + `bash
agentsecrets secrets pull   # cloud to keychain
agentsecrets secrets push   # keychain to cloud
` + "```" + `

## SECRET MANAGEMENT

` + "```" + `bash
agentsecrets secrets list                   # key names only, never values
agentsecrets secrets list --project NAME    # keys for specific project
agentsecrets secrets delete KEY_NAME        # remove a secret
` + "```" + `

If a key is missing, NEVER ask the user to paste the value into chat.
Tell them to run this in their own terminal:

` + "```" + `bash
agentsecrets secrets set KEY_NAME=value
` + "```" + `

Wait for confirmation, then verify with ` + "`" + `agentsecrets secrets list` + "`" + `.

Standard naming: SERVICE_KEY or SERVICE_TOKEN (uppercase, underscores)
Examples: STRIPE_KEY, OPENAI_KEY, GITHUB_TOKEN, PAYSTACK_KEY, SENDGRID_KEY

## MAKE AUTHENTICATED API CALLS

Always use ` + "`" + `agentsecrets call` + "`" + ` — never curl or direct HTTP with credentials.

` + "```" + `bash
# GET
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY

# POST with body
agentsecrets call \
  --url https://api.stripe.com/v1/charges \
  --method POST \
  --bearer STRIPE_KEY \
  --body '{"amount":1000,"currency":"usd","source":"tok_visa"}'

# PUT
agentsecrets call --url https://api.example.com/resource/123 --method PUT --bearer KEY --body '{}'

# DELETE
agentsecrets call --url https://api.example.com/resource/123 --method DELETE --bearer KEY

# Custom header
agentsecrets call --url https://api.sendgrid.com/v3/mail/send --method POST --header X-Api-Key=SENDGRID_KEY --body '{}'

# Query parameter
agentsecrets call --url "https://maps.googleapis.com/maps/api/geocode/json?address=Lagos" --query key=GOOGLE_MAPS_KEY

# Basic auth
agentsecrets call --url https://jira.example.com/rest/api/2/issue --basic JIRA_CREDS

# JSON body injection
agentsecrets call --url https://api.example.com/auth --body-field client_secret=SECRET

# Form field
agentsecrets call --url https://oauth.example.com/token --form-field api_key=KEY

# Multiple credentials
agentsecrets call --url https://api.example.com/data --bearer AUTH_TOKEN --header X-Org-ID=ORG_SECRET
` + "```" + `

## PROXY MODE

For multiple calls or framework integrations:

` + "```" + `bash
agentsecrets proxy start
agentsecrets proxy start --port 9000
agentsecrets proxy status
agentsecrets proxy stop
` + "```" + `

## AUDIT

After any significant workflow:

` + "```" + `bash
agentsecrets proxy logs
agentsecrets proxy logs --last 20
agentsecrets proxy logs --secret STRIPE_KEY
` + "```" + `

You will see: timestamp, method, target URL, key name, status code, duration. Never values.

## MCP

` + "```" + `bash
agentsecrets mcp install    # auto-configure Claude Desktop + Cursor
agentsecrets mcp serve      # start MCP server
` + "```" + `

### API Call Blocked by Allowlist
If ` + "`agentsecrets call`" + ` returns a 403 error stating the domain is not in the allowlist:
1. Do not ask the user to bypass the proxy.
2. Instruct the user to authorize the domain by running this in their terminal:
   ` + "`agentsecrets workspace allowlist add <domain>`" + `
3. Wait for their confirmation.
4. Retry the API call.

## CRITICAL RULES

1. NEVER display or log actual secret values
2. NEVER ask the user to paste a key value into chat
3. NEVER use curl for authenticated requests — always use agentsecrets call
4. ALWAYS run agentsecrets status at the start of a new session
5. ALWAYS run agentsecrets secrets diff before deployment workflows
6. You are the operator — manage the lifecycle autonomously
7. Respect the Zero-Trust allowlist — if a domain is blocked, guide the user to explicitly allow it using the allowlist add command.
`

func writeWorkflowFile() error {
	dir := filepath.Join(".", ".agent", "workflows")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "agentsecrets.md"), []byte(workflowContent), 0644)
}

