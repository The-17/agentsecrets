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
	Use:     "use [name]",
	Aliases: []string{"link"},
	Short:   "Switch to a project for the current directory",
	Args:    cobra.MaximumNArgs(1),
	RunE:    runProjectUse,
}

var projectUpdateCmd = &cobra.Command{
	Use:   "update [name]",
	Short: "Update a project's name or description",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runProjectUpdate,
}

var projectDeleteCmd = &cobra.Command{
	Use:   "delete [name]",
	Short: "Delete a project",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runProjectDelete,
}

var projectInviteCmd = &cobra.Command{
	Use:   "invite [email]",
	Short: "Invite a user to the current project",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runProjectInvite,
}

func init() {
	projectCmd.AddCommand(projectListCmd)
	projectCmd.AddCommand(projectCreateCmd)
	projectCmd.AddCommand(projectUseCmd)
	projectCmd.AddCommand(projectUpdateCmd)
	projectCmd.AddCommand(projectDeleteCmd)
	projectCmd.AddCommand(projectInviteCmd)
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

func runProjectUpdate(cmd *cobra.Command, args []string) error {
	var oldName string
	if len(args) > 0 {
		oldName = args[0]
	}

	if oldName == "" {
		if err := huh.NewInput().
			Title("Current Project Name").
			Description("Which project do you want to update?").
			Value(&oldName).
			Run(); err != nil {
			return nil
		}
	}

	var newName, desc string
	if err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("New Project Name").
				Description("Leave blank to keep current name").
				Value(&newName),
			huh.NewInput().
				Title("New Description").
				Description("Leave blank to keep current description").
				Value(&desc),
		),
	).Run(); err != nil {
		return nil
	}

	if newName == "" && desc == "" {
		ui.Info("No updates provided.")
		return nil
	}

	if err := ui.Spinner(fmt.Sprintf("Updating project '%s'...", oldName), func() error {
		return projectService.Update(oldName, newName, desc)
	}); err != nil {
		ui.Error("Failed to update project: " + err.Error())
		return nil
	}

	ui.Success(fmt.Sprintf("Project '%s' updated!", oldName))
	return nil
}

func runProjectDelete(cmd *cobra.Command, args []string) error {
	var name string
	if len(args) > 0 {
		name = args[0]
	}

	if name == "" {
		if err := huh.NewInput().
			Title("Project Name").
			Description("Which project do you want to delete?").
			Value(&name).
			Run(); err != nil {
			return nil
		}
	}

	var confirmed bool
	if err := huh.NewConfirm().
		Title(fmt.Sprintf("Are you sure you want to delete project '%s'? This cannot be undone.", name)).
		Value(&confirmed).
		Run(); err != nil || !confirmed {
		return nil
	}

	if err := ui.Spinner(fmt.Sprintf("Deleting project '%s'...", name), func() error {
		return projectService.Delete(name)
	}); err != nil {
		ui.Error("Failed to delete project: " + err.Error())
		return nil
	}

	ui.Success(fmt.Sprintf("Project '%s' deleted!", name))
	return nil
}

func runProjectInvite(cmd *cobra.Command, args []string) error {
	var email, role string
	if len(args) > 0 {
		email = args[0]
	}

	if email == "" {
		if err := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Invite Member").
					Description("Enter the email address to invite").
					Value(&email),
				huh.NewSelect[string]().
					Title("Role").
					Options(
						huh.NewOption("Member", "member"),
						huh.NewOption("Admin", "admin"),
					).
					Value(&role),
			),
		).Run(); err != nil {
			return nil
		}
	} else {
		if err := huh.NewSelect[string]().
			Title("Select Role").
			Options(
				huh.NewOption("Member", "member"),
				huh.NewOption("Admin", "admin"),
			).
			Value(&role).
			Run(); err != nil {
			return nil
		}
	}

	if err := ui.Spinner(fmt.Sprintf("Inviting %s...", email), func() error {
		return projectService.Invite(email, role)
	}); err != nil {
		ui.Error("Failed to invite: " + err.Error())
		return nil
	}

	ui.Success(fmt.Sprintf("Invited %s to project!", email))
	return nil
}
