package commands

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/projects"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/ui"
)

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

var targetWorkspaceFlag string

var projectTransferCmd = &cobra.Command{
	Use:   "transfer [project-name]",
	Short: "Transfer a project to another workspace",
	Long:  `Transfer a project and all its secrets to another workspace. Re-encrypts secrets with destination workspace key.`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runProjectTransfer,
}

var projectInviteCmd = &cobra.Command{
	Use:   "invite [email]",
	Short: "Invite a user to the current project",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runProjectInvite,
}

func init() {
	projectUseCmd.ValidArgsFunction = autocompleteProjects
	projectUpdateCmd.ValidArgsFunction = autocompleteProjects
	projectDeleteCmd.ValidArgsFunction = autocompleteProjects

	projectCmd.AddCommand(projectListCmd)
	projectCmd.AddCommand(projectCreateCmd)
	projectCmd.AddCommand(projectUseCmd)
	projectCmd.AddCommand(projectUpdateCmd)
	projectCmd.AddCommand(projectDeleteCmd)
	projectCmd.AddCommand(projectInviteCmd)
	projectTransferCmd.Flags().StringVarP(&targetWorkspaceFlag, "to-workspace", "w", "", "Target workspace name or ID")
	projectTransferCmd.ValidArgsFunction = autocompleteProjects
	projectCmd.AddCommand(projectTransferCmd)
}

func runProjectList(cmd *cobra.Command, args []string) error {
	var projs []projects.Project

	if err := ui.Spinner("Fetching projects...", func() error {
		var e error
		projs, e = app.Projects().List()
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
	currentProj, _ := config.LoadProjectConfig()

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

		pName := "  " + p.Name
		if currentProj != nil && currentProj.ProjectID == p.ID {
			pName = ui.BrandStyle.Render("→ " + p.Name)
		}

		rows[i] = []string{pName, wsName, desc}
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
		created, e = app.Projects().Create(name, desc)
		return e
	}); err != nil {
		ui.Error("Failed to create project: " + err.Error())
		return nil
	}

	cfg, _ := config.LoadGlobalConfig()
	workspaceID := config.GetSelectedWorkspaceID()
	_ = proxy.LogManagementEvent("CREATE", "project", fmt.Sprintf("Created project %s", created.Name), cfg.Email, workspaceID, created.ID, config.ResolveEnvironment())

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
			projs, e = app.Projects().List()
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
		used, e = app.Projects().Use(name)
		return e
	}); err != nil {
		ui.Error("Failed to use project: " + err.Error())
		return nil
	}

	cfg, _ := config.LoadGlobalConfig()
	workspaceID := config.GetSelectedWorkspaceID()
	_ = proxy.LogManagementEvent("LINK", "project", fmt.Sprintf("Linked directory to project %s", used.Name), cfg.Email, workspaceID, used.ID, config.ResolveEnvironment())

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
		return app.Projects().Update(oldName, newName, desc)
	}); err != nil {
		ui.Error("Failed to update project: " + err.Error())
		return nil
	}

	var projectID string
	if list, err := app.Projects().List(); err == nil {
		for _, p := range list {
			if p.Name == oldName || p.ID == oldName {
				projectID = p.ID
				break
			}
		}
	}
	cfg, _ := config.LoadGlobalConfig()
	workspaceID := config.GetSelectedWorkspaceID()
	targetName := oldName
	if newName != "" {
		targetName = newName
	}
	_ = proxy.LogManagementEvent("UPDATE", "project", fmt.Sprintf("Updated project %s", targetName), cfg.Email, workspaceID, projectID, config.ResolveEnvironment())

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

	var projectID string
	if list, err := app.Projects().List(); err == nil {
		for _, p := range list {
			if p.Name == name || p.ID == name {
				projectID = p.ID
				break
			}
		}
	}

	if projectID == "" {
		return fmt.Errorf("project %q not found", name)
	}

	var confirmed bool
	if err := huh.NewConfirm().
		Title(fmt.Sprintf("Are you sure you want to delete project '%s'? This cannot be undone.", name)).
		Value(&confirmed).
		Run(); err != nil || !confirmed {
		return nil
	}

	if err := verifyPasswordLocally(); err != nil {
		return err
	}

	if err := ui.Spinner(fmt.Sprintf("Deleting project '%s'...", name), func() error {
		return app.Projects().Delete(name)
	}); err != nil {
		ui.Error("Failed to delete project: " + err.Error())
		return nil
	}

	cfg, _ := config.LoadGlobalConfig()
	workspaceID := config.GetSelectedWorkspaceID()
	_ = proxy.LogManagementEvent("DELETE", "project", fmt.Sprintf("Deleted project %s", name), cfg.Email, workspaceID, projectID, config.ResolveEnvironment())

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
		return app.Projects().Invite(email, role)
	}); err != nil {
		ui.Error("Failed to invite: " + err.Error())
		return nil
	}

	ui.Success(fmt.Sprintf("Invited %s to project!", email))
	return nil
}

func autocompleteProjects(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	projs, err := app.Projects().List()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var completions []string
	for _, p := range projs {
		if strings.HasPrefix(strings.ToLower(p.Name), strings.ToLower(toComplete)) {
			completions = append(completions, p.Name)
		}
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func runProjectTransfer(cmd *cobra.Command, args []string) error {
	var projectName string
	if len(args) > 0 {
		projectName = args[0]
	}

	// 1. Prompt for project name if omitted
	if projectName == "" {
		var projs []projects.Project
		if err := ui.Spinner("Fetching projects...", func() error {
			var e error
			projs, e = app.Projects().List()
			return e
		}); err != nil {
			return fmt.Errorf("failed to fetch projects: %w", err)
		}
		if len(projs) == 0 {
			ui.Info("No projects found in the current workspace.")
			return nil
		}

		options := make([]huh.Option[string], len(projs))
		for i, p := range projs {
			options[i] = huh.NewOption(p.Name, p.Name)
		}

		err := huh.NewSelect[string]().
			Title("Select Project").
			Description("Which project do you want to transfer?").
			Options(options...).
			Value(&projectName).
			Run()
		if err != nil {
			return nil
		}
	}

	// 2. Resolve eligible target workspaces (where user is owner or admin)
	cfg, err := config.LoadGlobalConfig()
	if err != nil {
		return fmt.Errorf("failed to load global configuration: %w", err)
	}

	currentWsID := config.GetSelectedWorkspaceID()
	type wsChoice struct {
		ID   string
		Name string
	}
	var eligible []wsChoice

	for id, ws := range cfg.Workspaces {
		if id != currentWsID && (strings.EqualFold(ws.Role, "owner") || strings.EqualFold(ws.Role, "admin")) {
			eligible = append(eligible, wsChoice{ID: id, Name: ws.Name})
		}
	}

	if len(eligible) == 0 {
		ui.Error("You don't have any other workspace where you are an Owner or Admin.")
		return nil
	}

	targetWsID := targetWorkspaceFlag
	if targetWsID != "" {
		for _, ew := range eligible {
			if strings.EqualFold(ew.Name, targetWsID) {
				targetWsID = ew.ID
				break
			}
		}
	}

	if targetWsID == "" {
		wsOptions := make([]huh.Option[string], len(eligible))
		for i, ew := range eligible {
			wsOptions[i] = huh.NewOption(ew.Name, ew.ID)
		}

		err := huh.NewSelect[string]().
			Title("Destination Workspace").
			Description("Select workspace to transfer project to:").
			Options(wsOptions...).
			Value(&targetWsID).
			Run()
		if err != nil {
			return nil
		}
	}

	targetWsName := targetWsID
	for _, ew := range eligible {
		if ew.ID == targetWsID {
			targetWsName = ew.Name
			break
		}
	}

	// 3. Confirm with user
	var confirmed bool
	err = huh.NewConfirm().
		Title(fmt.Sprintf("Transfer project '%s' to workspace '%s'?", projectName, targetWsName)).
		Description("Secrets will be re-encrypted using the destination workspace's zero-knowledge key.").
		Value(&confirmed).
		Run()
	if err != nil || !confirmed {
		return nil
	}

	// 4. Execute transfer with spinner
	var result *projects.ProjectTransferResult
	err = ui.Spinner(fmt.Sprintf("Re-encrypting and transferring project '%s'...", projectName), func() error {
		var e error
		result, e = app.Projects().Transfer(projectName, targetWsID)
		return e
	})
	if err != nil {
		ui.Error("Failed to transfer project: " + err.Error())
		return nil
	}

	fmt.Println()
	ui.Success(fmt.Sprintf("Project '%s' successfully transferred to workspace '%s'!", result.ProjectName, result.TargetWorkspaceName))
	ui.Info(fmt.Sprintf("Re-encrypted and migrated %d secret(s).", result.SecretsTransferred))
	return nil
}
