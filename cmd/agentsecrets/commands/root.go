package commands

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/The-17/agentsecrets/pkg/workspaces"
)

// Version is set at build time via ldflags
var Version = "dev"

var (
	authService      *auth.Service
	workspaceService *workspaces.Service
)

// rootCmd is the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "agentsecrets",
	Short: "Secure secrets management for the AI era",
	Long: lipgloss.JoinVertical(lipgloss.Left,
		"",
		ui.BrandStyle.Render("AgentSecrets"),
		ui.DimStyle.Render("   Zero-knowledge secrets manager for AI-assisted development"),
		"",
		ui.LabelStyle.Render("   Manage secrets across projects, teams, and environments."),
		ui.LabelStyle.Render("   AI assistants can use this tool without seeing secret values."),
		"",
		ui.DimStyle.Render("   Get started:"),
		"   "+ui.BrandStyle.Render("agentsecrets init")+"        "+ui.LabelStyle.Render("Create a new account"),
		"   "+ui.BrandStyle.Render("agentsecrets login")+"       "+ui.LabelStyle.Render("Login to existing account"),
		"   "+ui.BrandStyle.Render("agentsecrets status")+"      "+ui.LabelStyle.Render("Show current session info"),
		"",
	),
	Version: Version,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Create the API client with a token provider function.
	apiClient := api.NewClient(func() string {
		return config.GetAccessToken()
	})

	// Create the shared services
	authService = auth.NewService(apiClient)
	workspaceService = workspaces.NewService(apiClient)

	// Register all subcommands
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(workspaceCmd)
}
