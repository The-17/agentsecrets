package commands

import (
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/projects"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var projectService *projects.Service

// InitProjectService sets up the service for the CLI
func InitProjectService(client *api.Client) {
	projectService = projects.NewService(client)
}

var projectCmd = &cobra.Command{
	Use:   "project",
	Short: "Manage your projects",
	Long:  `Manage projects to organize your secrets. Projects belong to workspaces.`,
}

var projectListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all your projects",
	RunE:  runProjectList,
}

var projectCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new project",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runProjectCreate,
}

var projectUseCmd = &cobra.Command{
	Use:   "use [name]",
	Short: "Switch to a project for the current directory",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runProjectUse,
}

func init() {
	projectCmd.AddCommand(projectListCmd)
	projectCmd.AddCommand(projectCreateCmd)
	projectCmd.AddCommand(projectUseCmd)
}

func runProjectList(cmd *cobra.Command, args []string) error {
	var projs []projects.Project

	if err := ui.Spinner("Fetching projects...", func() error {
		var e error
		projs, e = projectService.List()
		return e
	}); err != nil {
		ui.Error("Failed to list projects: " + err.Error())
		return nil
	}

	if len(projs) == 0 {
		ui.Info("No projects found. Create one with 'agentsecrets project create'.")
		return nil
	}

	// Fetch global config to map workspace IDs to names
	cfg, _ := config.LoadGlobalConfig()
	
	headers := []string{"Project", "Workspace", "Description"}
	rows := make([][]string, len(projs))

	for i, p := range projs {
		wsName := ui.DimStyle.Render("Unknown")
		if cfg != nil && cfg.Workspaces != nil {
			if ws, ok := cfg.Workspaces[p.WorkspaceID]; ok {
				wsName = ws.Name
			}
		}

		desc := p.Description
		if desc == "" {
			desc = "—"
		}

		rows[i] = []string{p.Name, wsName, desc}
	}

	renderedTable := ui.RenderTable(headers, rows)
	tableWidth := lipgloss.Width(renderedTable)

	fmt.Println()
	title := ui.BannerStr("Your Projects")
	fmt.Println(lipgloss.NewStyle().Width(tableWidth).Align(lipgloss.Center).Render(title))
	fmt.Println(renderedTable)
	fmt.Println()

	return nil
}

func runProjectCreate(cmd *cobra.Command, args []string) error {
	var name, desc string

	if len(args) > 0 {
		name = args[0]
	}

	if name == "" {
		err := huh.NewInput().
			Title("Project Name").
			Description("What should we call this project?").
			Value(&name).
			Validate(func(s string) error {
				if s == "" {
					return fmt.Errorf("name is required")
				}
				return nil
			}).
			Run()
		if err != nil {
			return nil
		}
	}

	err := huh.NewInput().
		Title("Description").
		Description("Optional project description").
		Value(&desc).
		Run()
	if err != nil {
		return nil
	}

	var created *projects.Project

	if err := ui.Spinner("Creating project...", func() error {
		var e error
		created, e = projectService.Create(name, desc)
		return e
	}); err != nil {
		ui.Error("Failed to create project: " + err.Error())
		return nil
	}

	fmt.Println()
	ui.Success(fmt.Sprintf("Project '%s' created and selected!", created.Name))
	return nil
}

func runProjectUse(cmd *cobra.Command, args []string) error {
	var name string
	var err error

	if len(args) > 0 {
		name = args[0]
	}

	if name == "" {
		// Fetch projects for selection
		var projs []projects.Project

		if err = ui.Spinner("Fetching projects...", func() error {
			var e error
			projs, e = projectService.List()
			return e
		}); err != nil {
			ui.Error("Failed to fetch projects: " + err.Error())
			return nil
		}

		if len(projs) == 0 {
			ui.Info("No projects found. Create one with 'agentsecrets project create'.")
			return nil
		}

		options := make([]huh.Option[string], len(projs))
		for i, p := range projs {
			options[i] = huh.NewOption(p.Name, p.Name)
		}

		err = huh.NewSelect[string]().
			Title("Select Project").
			Description("Which project would you like to use for this directory?").
			Options(options...).
			Value(&name).
			Run()
		if err != nil {
			return nil
		}
	}

	var used *projects.Project

	if err = ui.Spinner(fmt.Sprintf("Selecting project '%s'...", name), func() error {
		var e error
		used, e = projectService.Use(name)
		return e
	}); err != nil {
		ui.Error("Failed to use project: " + err.Error())
		return nil
	}

	fmt.Println()
	ui.Success(fmt.Sprintf("Now using project '%s'!", used.Name))
	return nil
}
