package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/config"
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
	var modeToUse int

	// Phase 1: Global Setup (Self-Contained)
	if !config.GlobalConfigExists() {
		ui.Info("Setting up AgentSecrets...")

		if err := config.InitGlobalConfig(); err != nil {
			return fmt.Errorf("failed to initialize global config: %w", err)
		}

		// First-ever run: prompt for storage mode unless flag passed
		modeToUse = storageMode
		if !cmd.Flags().Changed("storage-mode") {
			var modeChoice string
			err := huh.NewSelect[string]().
				Title("How would you like secrets to be stored locally by default?").
				Options(
					huh.NewOption("1. Keychain only (recommended) — values never written to disk.\n   .env.example created with key names only.", "1"),
					huh.NewOption("2. .env file — plaintext file, compatible with all existing tooling.", "2"),
				).
				Value(&modeChoice).
				Run()

			if err == nil {
				if modeChoice == "2" {
					modeToUse = 2
				} else {
					modeToUse = 1
				}
			}
		}

		if err := config.SetStorageMode(modeToUse); err != nil {
			return fmt.Errorf("failed to set storage mode: %w", err)
		}

		// Set default environment
		if err := config.SetSelectedEnvironment("development"); err != nil {
			return fmt.Errorf("failed to set default environment: %w", err)
		}

		_ = writeWorkflowFile()

		ui.Banner("AgentSecrets")
		fmt.Println()

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
		if choice == "signup" {
			if err := runSignup(); err != nil {
				return err
			}
		} else {
			if err := runLoginFlow(); err != nil {
				return err
			}
		}

		fmt.Println() // Spacer before project setup
	} else {
		// Subsequent runs: use global default
		modeToUse = config.GetStorageMode()
	}

	// Flag override (applies to both flows)
	if cmd.Flags().Changed("storage-mode") {
		modeToUse = storageMode
	}

	// Phase 2: Project Setup
	root, _ := config.GetProjectRoot()
	if root != "" && !forceReinit {
		ui.Info("Project already initialised in this directory.")
		project, err := config.LoadProjectConfig()
		if err == nil && project != nil {
			ui.StatusRow("Name", project.ProjectName)
			ui.StatusRow("ID", project.ProjectID)
			ui.StatusRow("Workspace", project.WorkspaceName)
		}
		return nil
	}

	_ = ui.Spinner("Initialising project wrapper...", func() error {
		if err := config.InitProjectConfig(modeToUse); err != nil {
			return fmt.Errorf("failed to initialize project config: %w", err)
		}

		// If mode 2, create all .env files for standard environments
		if modeToUse == 2 {
			for _, envName := range config.ValidEnvironments {
				filename := ".env"
				if envName != "development" {
					filename = ".env." + envName
				}
				path := filepath.Join(".", filename)
				if _, err := os.Stat(path); os.IsNotExist(err) {
					_ = os.WriteFile(path, []byte("# AgentSecrets environment: "+envName+"\n"), 0644)
				}
			}
		}

		// Update .gitignore with environment-specific .env files
		updateGitignore(".")
		return nil
	})

	ui.Success("Project initialised successfully!")
	ui.Info("Run 'agentsecrets project create <name>' or 'agentsecrets project use <name>' to link this folder.")

	// Phase 3: Setup keychain-auth daemon (Disabled in v1.3.0)
	/*
		if err := ui.Spinner("Configuring secure keychain daemon...", func() error {
			return keychainauth.AutoSetup()
		}); err != nil {
			ui.Warning(fmt.Sprintf("Failed to auto-configure keychain-auth: %v", err))
			ui.Info("You may need to run 'agentsecrets setup keychain-auth' later, or install manually:")
			ui.Info("  brew install The-17/tap/keychain-auth")
		}
	*/

	return nil
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
		ui.ErrorWithSuggestions(
			fmt.Errorf("Signup failed: %w", err),
			"If you already have an account, run 'agentsecrets login' instead.",
			"Check your email syntax and ensure you are not already registered.",
			"Verify your network connection to the AgentSecrets service.",
		)
		return nil
	}

	ui.Success("Account created and logged in!")
	return nil
}

func runLoginFlow() error {
	return performLogin()
}

const workflowContent = `---
description: Zero-knowledge secrets infrastructure — AI agents manage the complete credential lifecycle without ever seeing values
---

# AgentSecrets — Zero-Knowledge Secrets Infrastructure

You manage the full credentials lifecycle autonomously using the ` + "`agentsecrets`" + ` CLI.
**You are the operator. You never see the actual credential values.**

## Security & Privacy Rules
- **Domain Bound:** You can autonomously make authenticated API calls via ` + "`agentsecrets call`" + `, but you are cryptographically bound by the workspace domain allowlist. 
- **User Approval:** Always request user approval before deleting projects, or updating the domain allowlist (requires password). You cannot modify workspace membership; that is a user-only operation.
- **Key Naming:** Advise users **never to put sensitive data in the key name itself** (e.g. use ` + "`STRIPE_KEY`" + `, not ` + "`STRIPE_sk_live...`" + `). Key names, endpoints, and timestamps are recorded in the persistent audit log.
- **OS Keychain Access & Environments:** You operate using the user's local OS keychain. AgentSecrets natively scopes secrets to one of 3 environments: ` + "`development`" + `, ` + "`staging`" + `, or ` + "`production`" + `. Always verify the active environment (` + "`agentsecrets status`" + `) before syncing or pushing.

## Core Workflow Commands
Always start by verifying context:
` + "```" + `bash
agentsecrets status # Shows workspace, project, environment
agentsecrets secrets list # Lists available keys
` + "```" + `

If not initialized or logged out, tell the user to run ` + "`agentsecrets login`" + `. For new projects, run ` + "`agentsecrets init --storage-mode 1`" + `.

### Managing Secrets
` + "```" + `bash
# User runs this in their terminal (do not ask them to paste it in chat)
agentsecrets secrets set KEY_NAME=value

# You can run these
agentsecrets secrets list
agentsecrets secrets diff
agentsecrets secrets push
agentsecrets secrets pull
` + "```" + `

### Making Authenticated API Calls
Instead of using ` + "`curl`" + `, always use the ` + "`call`" + ` proxy. The proxy injects the secret securely:
` + "```" + `bash
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY
agentsecrets call --url https://api.example.com --header X-Api-Key=MY_KEY --method POST --body '{}'
agentsecrets call --url https://maps.example.com --query key=MAPS_KEY
agentsecrets call --url https://jira.example.com --basic JIRA_CREDS
` + "```" + `

### Environment Injection
To wrap standard tools so they receive secrets as environment variables:
` + "```" + `bash
agentsecrets env -- npm run dev
agentsecrets env -- stripe mcp
` + "```" + `
For OpenClaw SecretRef injection, run:
` + "```" + `bash
agentsecrets exec
` + "```" + `

### Environments & Workspaces
` + "```" + `bash
agentsecrets environment switch production # (Ask for confirmation first)
agentsecrets project create OPENCLAW_MANAGER
agentsecrets project use OPENCLAW_MANAGER
` + "```" + `

### Troubleshooting & Docs
Use ` + "`agentsecrets proxy logs --last 10`" + ` to view the local audit trail for failed requests. 
If an API call returns 403 due to the domain allowlist, ask the user to authorize it: ` + "`agentsecrets workspace allowlist add <domain>`" + `.
If you need to know a command, run ` + "`agentsecrets --help`" + `.
To search the official AgentSecrets documentation, use the API below to get a list of matching topics and snippets. You can then ` + "`curl`" + ` the specific URL from the results to read the full page:
` + "```" + `bash
curl -G "https://agentsecrets.theseventeen.co/api/search" --data-urlencode "q=your query here"
` + "```" + `
If you need to read the full, complete documentation in a single Markdown file, curl:
` + "```" + `bash
curl -s "https://agentsecrets.theseventeen.co/llms-full.txt"
` + "```" + `
`

func writeWorkflowFile() error {
	dir := filepath.Join(".", ".agent", "workflows")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "agentsecrets.md"), []byte(workflowContent), 0644)
}

// updateGitignore adds environment-specific .env files to .gitignore if not already present.
func updateGitignore(projectRoot string) {
	gitignorePath := filepath.Join(projectRoot, ".gitignore")
	entries := []string{".env", ".env.development", ".env.staging", ".env.production"}

	// Read existing content
	existing := ""
	if data, err := os.ReadFile(gitignorePath); err == nil {
		existing = string(data)
	}

	// Append only missing entries
	var toAdd []string
	for _, entry := range entries {
		if !strings.Contains(existing, entry) {
			toAdd = append(toAdd, entry)
		}
	}

	if len(toAdd) > 0 {
		newContent := existing
		if len(newContent) > 0 && !strings.HasSuffix(newContent, "\n") {
			newContent += "\n"
		}
		newContent += "\n# AgentSecrets environment files\n"
		newContent += strings.Join(toAdd, "\n")
		newContent += "\n"
		_ = os.WriteFile(gitignorePath, []byte(newContent), 0644)
	}
}
