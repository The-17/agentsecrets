package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/projects"
	"github.com/The-17/agentsecrets/pkg/secrets"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var forceReinit bool
var storageMode int
var initServerFlag string
var initProjectFlag string
var initWorkflowsFlag bool

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize AgentSecrets and create or connect your account",
	Long: `Initialize AgentSecrets for your account and local environment.

	This sets up the configuration directory and prompts you to create a
	new account or connect an existing one.

	What happens:
	1. Creates ~/.agentsecrets/ (global config)
	2. Creates .agentsecrets/ (project config in current directory)
	3. Creates .agent/workflows/agentsecrets.md (teaches AI assistants to use AgentSecrets)
	4. Prompts to select server (Cloud or Self-Hosted)
	5. Prompts to create account or login
	6. Generates encryption keypair (for new accounts)
	7. Stores credentials securely
	8. Links this directory to a project (use --project <name> to skip the prompt)

	Agent instruction files are opt-in with --workflows. Most repositories do
	not want generated .agent/ files committed by a setup command.

	When this finishes the directory is bound to a project, so secrets are
	available however you consume them: 'agentsecrets env -- <command>',
	'agentsecrets call', the proxy, or agents through the SDK.`,
	RunE: runInit,
}

func init() {
	initCmd.Flags().BoolVarP(&forceReinit, "force", "f", false, "Skip reinitialize confirmation")
	initCmd.Flags().IntVar(&storageMode, "storage-mode", 1, "Set storage mode (1: keychain only, 2: keychain & .env file)")
	initCmd.Flags().StringVar(&initServerFlag, "server", "", "Custom AgentSecrets server endpoint URL")
	initCmd.Flags().StringVar(&initProjectFlag, "project", "", "Project to link this directory to (skip the prompt; created if it does not exist)")
	initCmd.Flags().BoolVar(&initWorkflowsFlag, "workflows", false, "Write .agent/workflows/ agent instructions into this repository")
}

func runInit(cmd *cobra.Command, args []string) error {
	var modeToUse int

	// Capture this before --server writes a config file. Otherwise a fresh
	// machine with --server skips the entire first-run branch: no server
	// picker, no storage mode prompt, no default environment.
	firstRun := !config.GlobalConfigExists()

	if initServerFlag != "" {
		if err := config.SetGlobalServerURL(initServerFlag); err != nil {
			return fmt.Errorf("invalid server URL: %w", err)
		}
	}

	// Phase 1: Global Setup (Self-Contained)
	if firstRun || !config.IsAuthenticated() {
		ui.Info("Setting up AgentSecrets...")

		if firstRun {
			if err := config.InitGlobalConfig(); err != nil {
				return fmt.Errorf("failed to initialize global config: %w", err)
			}

			// Server target selection if not explicitly passed
			if !cmd.Flags().Changed("server") {
				var serverChoice string
				err := huh.NewSelect[string]().
					Title("Where is your AgentSecrets backend located?").
					Options(
						huh.NewOption("1. AgentSecrets Server (The Seventeen Engineering)", "default"),
						huh.NewOption("2. Self-Hosted Server (Custom URL)", "selfhost"),
					).
					Value(&serverChoice).
					Run()

				if err == nil && serverChoice == "selfhost" {
					var customURL string
					_ = huh.NewInput().
						Title("Enter your self-hosted server URL:").
						Placeholder("http://localhost:8000 or https://secrets.internal.corp/api").
						Value(&customURL).
						Run()

					if customURL != "" {
						_ = config.SetGlobalServerURL(customURL)
					}
				}
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
		} else {
			// Subsequent runs (already exists but not authenticated): use global default
			modeToUse = config.GetStorageMode()
		}

		if initWorkflowsFlag {
			_ = writeWorkflowFile()
		}

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
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return errors.New(errors.ErrUsage,
					"init needs a terminal to ask whether to sign up or log in",
					fmt.Errorf("run 'agentsecrets init' in an interactive shell, or run 'agentsecrets login'"))
			}
			ui.Info("Setup cancelled.")
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
		if project, err := config.LoadProjectConfig(); err == nil && project != nil && project.ProjectID != "" {
			ui.Info("Project already initialised in this directory.")
			ui.StatusRow("Name", project.ProjectName)
			ui.StatusRow("ID", project.ProjectID)
			ui.StatusRow("Workspace", project.WorkspaceName)
			return nil
		}
	}

	if err := ui.Spinner("Initialising project wrapper...", func() error {
		if err := config.InitProjectConfig(modeToUse); err != nil {
			return fmt.Errorf("failed to initialize project config: %w", err)
		}

		// Create AI agent workflow/instruction files only when asked. Generated
		// .agent/ files otherwise appear as untracked noise in the repository.
		if initWorkflowsFlag {
			_ = writeWorkflowFile()
		}

		// If mode 2, create all .env files for standard environments
		if modeToUse == 2 {
			for _, envName := range config.StandardEnvironments {
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
	}); err != nil {
		return err
	}

	ui.Success("Project wrapper initialised.")
	return linkProjectForInit()
}

// initProjectNameDefault derives a usable default project name from the working
// directory, so the common case needs one keystroke.
func initProjectNameDefault() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	return filepath.Base(dir)
}

// isProjectNotFound reports whether a projects.Use failure means "no such
// project in this workspace". Projects resolve inside the selected workspace,
// so the same name may exist elsewhere; that still counts as not found here.
func isProjectNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "404") || strings.Contains(msg, "not found")
}

// linkOrCreate binds the directory to the project named name, creating it when
// the workspace has no such project yet. This is the create-or-use behaviour:
// a developer who just cloned a repo should not have to know which case they
// are in before running one command.
func linkOrCreate(name string) (*projects.Project, error) {
	var bound *projects.Project
	err := ui.Spinner(fmt.Sprintf("Linking project '%s'...", name), func() error {
		var e error
		bound, e = app.Projects().Use(name)
		return e
	})
	if err == nil {
		return bound, nil
	}
	if !isProjectNotFound(err) {
		return nil, err
	}

	if err := ui.Spinner(fmt.Sprintf("No project '%s' yet, creating it...", name), func() error {
		var e error
		bound, e = app.Projects().Create(name, "")
		return e
	}); err != nil {
		return nil, err
	}
	return bound, nil
}

// linkProjectForInit finishes init by leaving the directory bound to a project,
// so secrets are usable through env, call, the proxy or the SDK. Without this,
// init printed success and then asked for a second command, and every one of
// those paths failed with "no active project" until the user linked one.
func linkProjectForInit() error {
	name := strings.TrimSpace(initProjectFlag)
	interactive := term.IsTerminal(int(os.Stdin.Fd()))

	// The directory name is the default even without a terminal. init is an
	// explicit setup command, and create-or-use makes this safe: an existing
	// project with that name is linked instead of duplicated. --project is for
	// callers that need a different name.
	if name == "" && interactive {
		defaultName := initProjectNameDefault()
		var projs []projects.Project
		if err := ui.Spinner("Looking up projects...", func() error {
			var e error
			projs, e = app.Projects().List()
			return e
		}); err != nil {
			ui.Warning("Could not list projects: " + err.Error())
		}

		options := []huh.Option[string]{
			huh.NewOption(fmt.Sprintf("Project %q (create it if missing)", defaultName), defaultName),
		}
		for _, p := range projs {
			if strings.EqualFold(p.Name, defaultName) {
				continue // already offered as the create/default entry
			}
			options = append(options, huh.NewOption("Use existing project "+p.Name, p.Name))
		}

		if err := huh.NewSelect[string]().
			Title("Which project should this directory use?").
			Options(options...).
			Value(&name).
			Run(); err != nil {
			return nil
		}
	}

	name = strings.TrimSpace(name)
	if name == "" {
		name = initProjectNameDefault()
	}
	if name == "" {
		return errors.New(errors.ErrUsage, "could not derive a project name from this directory",
			fmt.Errorf("re-run with --project <name>"))
	}

	bound, err := linkOrCreate(name)
	if err != nil {
		return err
	}

	fmt.Println()
	ui.Success(fmt.Sprintf("Project '%s' linked to this directory.", bound.Name))
	if ws := displayScopeName(cachedWorkspaceName(bound.WorkspaceID), bound.WorkspaceID); ws != "" {
		ui.StatusRow("Workspace", ws)
	}
	ui.Info("Secrets are ready. Inject them with 'agentsecrets env -- <command>', call an API with 'agentsecrets call', or expose them to an agent through the SDK.")
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
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New(errors.ErrUsage,
				"signing up asks for your name, email and password, and there is no terminal here to type them in",
				fmt.Errorf("run 'agentsecrets init' in an interactive shell"))
		}
		return nil // cancelled by the user
	}

	fmt.Println()

	// Create account with spinner
	var result *auth.LoginResult
	if err := ui.Spinner("Creating your account...", func() error {
		var err error
		result, err = app.Auth().Signup(auth.SignupRequest{
			FirstName: firstName,
			LastName:  lastName,
			Email:     email,
			Password:  password,
		})
		return err
	}); err != nil {
		return errors.WithSuggestions(errors.FromError(err).Code, "signup failed", err,
			"If you already have an account, run 'agentsecrets login' instead.",
			"Check your email syntax and ensure you are not already registered.",
			"Verify your network connection to the AgentSecrets service.")
	}

	ui.Success("Account created and logged in!")
	showVaultResult(result, password)
	return nil
}

func runLoginFlow() error {
	return performLogin()
}

func writeWorkflowFile() error {
	dir := filepath.Join(".", ".agent", "workflows")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	content := strings.TrimSpace(workflowContentTemplate)
	if err := os.WriteFile(filepath.Join(dir, "agentsecrets.md"), []byte(content), 0644); err != nil {
		return err
	}
	// Ship the references beside the workflow so the project copy has the same
	// depth as an installed skill. Same generated source, so they cannot drift.
	refDir := filepath.Join(dir, "agentsecrets")
	if err := os.MkdirAll(refDir, 0755); err != nil {
		return err
	}
	for name, body := range SkillReferences() {
		if err := os.WriteFile(filepath.Join(refDir, name), []byte(body), 0644); err != nil {
			return err
		}
	}
	return nil
}

// updateGitignore keeps the wrapper setup path aligned with the write path.
// The real rule lives next to the .env writer so it also runs on projects
// created without init.
func updateGitignore(projectRoot string) {
	if err := secrets.EnsureEnvGitignore(projectRoot); err != nil {
		ui.Warning("Could not add .env files to .gitignore: " + err.Error())
	}
}
