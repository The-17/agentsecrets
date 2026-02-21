package commands

import (
	"fmt"
	"sort"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/The-17/agentsecrets/pkg/workspaces"
)


var workspaceCmd = &cobra.Command{
	Use:   "workspace",
	Short: "Manage workspaces",
	Long: `List, switch, and create workspaces.
	Workspaces allow you to separate secrets for different teams or personal use.`,
	RunE: runWorkspaceList,
}

func init() {
	workspaceCmd.AddCommand(
		&cobra.Command{
			Use:     "list",
			Aliases: []string{"ls"},
			Short:   "List all workspaces",
			RunE:    runWorkspaceList,
		},
		&cobra.Command{
			Use:   "switch [name]",
			Short: "Switch active workspace",
			Args:  cobra.MaximumNArgs(1),
			RunE:  runWorkspaceSwitch,
		},
		&cobra.Command{
			Use:   "create [name]",
			Short: "Create a new workspace",
			Args:  cobra.MaximumNArgs(1),
			RunE:  runWorkspaceCreate,
		},
		&cobra.Command{
			Use:   "invite [email]",
			Short: "Invite a user to the current workspace",
			Args:  cobra.MaximumNArgs(1),
			RunE:  runWorkspaceInvite,
		},
		&cobra.Command{
			Use:   "members",
			Short: "List members of the current workspace",
			RunE:  runWorkspaceMembers,
		},
		&cobra.Command{
			Use:   "remove [email]",
			Short: "Remove a member from the workspace",
			Args:  cobra.ExactArgs(1),
			RunE:  runWorkspaceRemove,
		},
	)
}


// requireConfig loads the global config and returns an error if the workspace
// list is empty, printing a helpful hint in that case.
func requireConfig() (*config.GlobalConfig, error) {
	cfg, err := config.LoadGlobalConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	if len(cfg.Workspaces) == 0 {
		ui.Info("No workspaces found. Run 'agentsecrets login' to sync.")
		return nil, nil // nil config signals "nothing to do"
	}
	return cfg, nil
}

// requireWorkspaceID returns the currently selected workspace ID or an error.
func requireWorkspaceID() (string, error) {
	id := config.GetSelectedWorkspaceID()
	if id == "" {
		return "", fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
	}
	return id, nil
}

// Handlers

func runWorkspaceList(_ *cobra.Command, _ []string) error {
	cfg, err := requireConfig()
	if err != nil || cfg == nil {
		return err
	}

	// Sort workspace IDs for consistent display order.
	ids := make([]string, 0, len(cfg.Workspaces))
	for id := range cfg.Workspaces {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	fmt.Println()
	ui.Banner("Workspaces")
	ui.Divider()

	for _, id := range ids {
		ws := cfg.Workspaces[id]

		marker := "  "
		if id == cfg.SelectedWorkspaceID {
			marker = ui.BrandStyle.Render("→ ")
		}

		wsType := ws.Type
		if wsType == "" {
			wsType = "shared"
		}

		fmt.Printf("%s %s %s\n", marker, ui.ValStyle.Render(ws.Name), ui.DimStyle.Render("("+wsType+")"))
	}

	fmt.Println()
	return nil
}

func runWorkspaceSwitch(_ *cobra.Command, args []string) error {
	cfg, err := requireConfig()
	if err != nil || cfg == nil {
		return err
	}

	var selectedID string

	if len(args) > 0 {
		// Name provided — find it directly.
		name := args[0]
		for id, ws := range cfg.Workspaces {
			if ws.Name == name || (name == "personal" && ws.Type == "personal") {
				selectedID = id
				break
			}
		}
		if selectedID == "" {
			return fmt.Errorf("workspace %q not found", name)
		}
	} else {
		// Build sorted option list for the interactive picker.
		options := make([]huh.Option[string], 0, len(cfg.Workspaces))
		for id, ws := range cfg.Workspaces {
			label := ws.Name
			if ws.Type == "shared" {
				label += " (shared)"
			}
			options = append(options, huh.NewOption(label, id))
		}
		sort.Slice(options, func(i, j int) bool { return options[i].Key < options[j].Key })

		if err := huh.NewSelect[string]().
			Title("Switch active workspace").
			Options(options...).
			Value(&selectedID).
			Run(); err != nil {
			return nil // user cancelled
		}
	}

	if err := config.SetSelectedWorkspaceID(selectedID); err != nil {
		return fmt.Errorf("failed to update active workspace: %w", err)
	}

	ui.Success(fmt.Sprintf("Switched to workspace: %s", cfg.Workspaces[selectedID].Name))
	return nil
}

func runWorkspaceCreate(_ *cobra.Command, args []string) error {
	name := firstArg(args)

	if name == "" {
		if err := huh.NewInput().
			Title("Workspace Name").
			Description("What should we call your new workspace?").
			Value(&name).
			Run(); err != nil {
			return nil // user cancelled
		}
	}

	if err := ui.Spinner(fmt.Sprintf("Creating workspace (%s)...", name), func() error {
		return workspaceService.Create(name)
	}); err != nil {
		return err
	}

	ui.Success(fmt.Sprintf("Workspace %s created and selected!", name))
	return nil
}

func runWorkspaceInvite(_ *cobra.Command, args []string) error {
	workspaceID, err := requireWorkspaceID()
	if err != nil {
		return err
	}

	email := firstArg(args)
	var role string

	// Collect both fields in one form when email isn't pre-supplied.
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
			return nil // user cancelled
		}
	} else {
		// Email given via arg — only ask for role.
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
		return workspaceService.Invite(workspaceID, email, role)
	}); err != nil {
		return err
	}

	ui.Success(fmt.Sprintf("Invited %s to workspace!", email))
	return nil
}

func runWorkspaceMembers(_ *cobra.Command, _ []string) error {
	workspaceID, err := requireWorkspaceID()
	if err != nil {
		return err
	}

	var members []workspaces.WorkspaceMember
	if err := ui.Spinner("Fetching members...", func() error {
		var e error
		members, e = workspaceService.Members(workspaceID)
		return e
	}); err != nil {
		return err
	}

	fmt.Println()
	ui.Banner("👥 Workspace Members")
	ui.Divider()

	for _, m := range members {
		status := ui.DimStyle.Render(m.Status)
		if m.Status == "active" {
			status = ui.BrandStyle.Render(m.Status)
		}
		fmt.Printf("  %s %s %s\n", ui.ValStyle.Render(m.Email), ui.LabelStyle.Render("("+m.Role+")"), status)
	}

	fmt.Println()
	return nil
}

func runWorkspaceRemove(_ *cobra.Command, args []string) error {
	email := args[0]

	workspaceID, err := requireWorkspaceID()
	if err != nil {
		return err
	}

	var confirmed bool
	if err := huh.NewConfirm().
		Title(fmt.Sprintf("Remove %s from workspace?", email)).
		Value(&confirmed).
		Run(); err != nil || !confirmed {
		return nil // user cancelled or declined
	}

	if err := ui.Spinner(fmt.Sprintf("Removing %s...", email), func() error {
		return workspaceService.RemoveMember(workspaceID, email)
	}); err != nil {
		return err
	}

	ui.Success(fmt.Sprintf("Removed %s from workspace.", email))
	return nil
}


// firstArg returns args[0] or "" — saves nil-check boilerplate at every call site.
func firstArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return ""
}