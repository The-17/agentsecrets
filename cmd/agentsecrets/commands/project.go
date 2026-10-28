package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"golang.org/x/term"

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
	Use:   "create [name] [description]",
	Short: "Create a new project",
	Long: `Create a new project in the selected workspace.

  agentsecrets project create backend "Payments backend"
  agentsecrets project create backend --description "Payments backend"

Without a name the CLI asks for one interactively. The description is optional
and is only asked for in that same interactive flow, so scripts and agents are
never left waiting on a prompt.`,
	Args: cobra.MaximumNArgs(2),
	RunE: runProjectCreate,
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

var projectTransferTo string

var projectTransferCmd = &cobra.Command{
	Use:   "transfer [name]",
	Short: "Transfer a project and all its secrets to another workspace",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runProjectTransfer,
}

func init() {
	projectUseCmd.ValidArgsFunction = autocompleteProjects
	projectUpdateCmd.ValidArgsFunction = autocompleteProjects
	projectDeleteCmd.ValidArgsFunction = autocompleteProjects
	projectCreateCmd.Flags().StringP("description", "d", "", "project description; without it, the description is only asked for in the interactive flow")

	projectCmd.AddCommand(projectListCmd)
	projectCmd.AddCommand(projectCreateCmd)
	projectCmd.AddCommand(projectUseCmd)
	projectCmd.AddCommand(projectUpdateCmd)
	projectCmd.AddCommand(projectDeleteCmd)
	projectCmd.AddCommand(projectInviteCmd)
	projectTransferCmd.Flags().StringVar(&projectTransferTo, "to", "", "destination workspace name or id")
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
	if len(args) > 1 {
		desc = args[1]
	}
	if flagDesc, _ := cmd.Flags().GetString("description"); flagDesc != "" {
		desc = flagDesc
	}

	// The name can come from the command line or from a prompt, never from
	// silence. A scripted call with no name must fail loudly instead of
	// hanging on a prompt that then cancels itself and reports success
	// without creating anything.
	nameWasPrompted := false
	interactive := term.IsTerminal(int(os.Stdin.Fd()))

	if name == "" {
		if !interactive {
			return fmt.Errorf("project name is required: agentsecrets project create <name> [description]")
		}
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
		nameWasPrompted = true
	}

	// The description is optional. Ask for it only inside the interactive flow
	// that already asked for the name; a caller that passed the name as an
	// argument is scripting and gets no surprise prompt. Cancel there is fine:
	// an empty description is a valid answer.
	if nameWasPrompted && desc == "" {
		_ = huh.NewInput().
			Title("Description").
			Description("Optional project description").
			Value(&desc).
			Run()
	}

	var created *projects.Project

	if err := ui.Spinner("Creating project...", func() error {
		var e error
		created, e = app.Projects().Create(name, desc)
		return e
	}); err != nil {
		return err
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

	if !confirmHuh(fmt.Sprintf("Are you sure you want to delete project '%s'? This cannot be undone.", name), "") {
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

func runProjectTransfer(cmd *cobra.Command, args []string) error {
	var name string
	if len(args) > 0 {
		name = args[0]
	}

	if name == "" {
		if err := huh.NewInput().
			Title("Project Name").
			Description("Which project do you want to transfer?").
			Value(&name).
			Run(); err != nil {
			return nil
		}
	}

	global, _ := config.LoadGlobalConfig()

	// Resolve the destination workspace (by name or id).
	targetRef := projectTransferTo
	if targetRef == "" {
		if global == nil || len(global.Workspaces) == 0 {
			ui.Error("No workspaces found. Run 'agentsecrets workspace list'.")
			return nil
		}
		options := make([]huh.Option[string], 0, len(global.Workspaces))
		for id, ws := range global.Workspaces {
			options = append(options, huh.NewOption(fmt.Sprintf("%s (%s)", ws.Name, ws.Type), id))
		}
		if err := huh.NewSelect[string]().
			Title("Destination Workspace").
			Description("You must be an owner or admin of the destination workspace.").
			Options(options...).
			Value(&targetRef).
			Run(); err != nil {
			return nil
		}
	}

	targetWorkspaceID, targetWorkspaceName := "", ""
	if global != nil {
		for id, ws := range global.Workspaces {
			if strings.EqualFold(id, targetRef) || strings.EqualFold(ws.Name, targetRef) {
				targetWorkspaceID = id
				targetWorkspaceName = ws.Name
				break
			}
		}
	}
	if targetWorkspaceID == "" {
		ui.Error(fmt.Sprintf("Workspace %q not found or not cached locally. Run 'agentsecrets workspace list'.", targetRef))
		return nil
	}

	if !confirmHuh(fmt.Sprintf("Transfer project '%s' to workspace '%s'? All secrets will be re-encrypted on this device.", name, targetWorkspaceName), "") {
		return nil
	}

	if err := verifyPasswordLocally(); err != nil {
		return err
	}

	var result *projects.TransferResult
	if err := ui.Spinner(fmt.Sprintf("Re-encrypting and transferring '%s'...", name), func() error {
		var e error
		result, e = app.Projects().Transfer(name, targetWorkspaceID)
		return e
	}); err != nil {
		ui.Error("Failed to transfer project: " + err.Error())
		return nil
	}

	cfg, _ := config.LoadGlobalConfig()
	workspaceID := config.GetSelectedWorkspaceID()
	_ = proxy.LogManagementEvent("TRANSFER", "project", fmt.Sprintf("Transferred project %s to %s", result.ProjectName, result.TargetWorkspaceName), cfg.Email, workspaceID, result.ProjectID, config.ResolveEnvironment())

	fmt.Println()
	ui.Success(fmt.Sprintf("Project '%s' transferred to '%s' (%d secrets re-encrypted).", result.ProjectName, result.TargetWorkspaceName, result.SecretsTransferred))
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
