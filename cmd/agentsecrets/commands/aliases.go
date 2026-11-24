package commands

import (
	"fmt"
	"strings"
	"sync"

	"github.com/spf13/cobra"
)

// aliasDef describes a verb-noun top-level shortcut that mirrors an existing
// canonical subcommand `src`. `group` is the noun-group parent whose
// PersistentPreRunE (auth/daemon middleware) applies when `src` doesn't define
// its own. `display` is the compact label shown in the root "Command Shortcuts"
// help section, using the (s) notation to fold the singular/plural pair onto one
// line (e.g. "list-secret(s)").
type aliasDef struct {
	use     string
	aliases []string
	display string
	src     *cobra.Command
	group   *cobra.Command
}

var (
	aliasOnce sync.Once
	// shortcutDisplays holds {display, short} rows for the root help section,
	// in registration order (grouped by noun). Populated by registerAliases.
	shortcutDisplays [][2]string
)

// addAliases appends alternate names to a command (used for singular/plural
// noun-group forms like secret/secrets, project/projects).
func addAliases(cmd *cobra.Command, names ...string) {
	if cmd == nil {
		return
	}
	cmd.Aliases = append(cmd.Aliases, names...)
}

// findSub returns the child of parent whose name matches, or nil. Used to reach
// subcommands that are declared as anonymous struct literals (workspace).
func findSub(parent *cobra.Command, name string) *cobra.Command {
	if parent == nil {
		return nil
	}
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

// mkTopAlias builds a top-level command that mirrors src exactly: same RunE,
// argument validation, flags, and shell completion. The effective pre-run
// middleware is inherited from src, or from its noun-group parent when src
// relies on the group's PersistentPreRunE. It is marked Hidden so cobra's
// default "Available Commands" list stays focused on the canonical
// noun-then-action tree; the shortcuts are instead surfaced in a dedicated
// "Command Shortcuts" section on the root help (see rootUsageTemplate).
func mkTopAlias(use string, aliases []string, src, group *cobra.Command) *cobra.Command {
	c := &cobra.Command{
		Use:               use,
		Aliases:           aliases,
		Short:             src.Short,
		Args:              src.Args,
		RunE:              src.RunE,
		ValidArgsFunction: src.ValidArgsFunction,
		Hidden:            true,
		SilenceErrors:     src.SilenceErrors,
		SilenceUsage:      src.SilenceUsage,
	}
	// Share the underlying flag pointers so `list-secrets --remote` toggles the
	// same variable as `secrets list --remote`.
	c.Flags().AddFlagSet(src.Flags())

	// Reproduce the effective middleware. Cobra runs the nearest
	// PersistentPreRunE in the chain; for a top-level shortcut that is either
	// src's own (e.g. `secrets list`, `logs`) or the noun group's inherited one.
	switch {
	case src.PersistentPreRunE != nil:
		c.PreRunE = src.PersistentPreRunE
	case group != nil && group.PersistentPreRunE != nil:
		c.PreRunE = group.PersistentPreRunE
	}
	return c
}

// registerAliases wires up the two ergonomic alias layers on top of the
// canonical command tree:
//
//  1. Noun groups accept singular OR plural (secret/secrets, project/projects).
//  2. Verb-noun top-level shortcuts in BOTH numbers (list-secret/list-secrets,
//     list-project/list-projects, set-secret/set-secrets) that invoke the same
//     logic, flags, and auth as the underlying subcommand. These are rendered in
//     a dedicated "Command Shortcuts" section on the root help.
//
// It is called from Execute() rather than an init() so every source command's
// flags and subcommands are guaranteed registered first, independent of Go's
// per-file init() ordering. Guarded by sync.Once so repeated Execute() calls
// (e.g. in tests) don't double-register.
func registerAliases() {
	aliasOnce.Do(func() {
		// Layer 1: singular/plural on the noun groups.
		addAliases(secretsCmd, "secret")
		addAliases(projectCmd, "projects")
		addAliases(workspaceCmd, "workspaces", "ws")
		addAliases(agentCmd, "agents")
		addAliases(logsCmd, "log")
		addAliases(environmentCmd, "environments")
		addAliases(serverCmd, "servers")
		addAliases(workspaceAllowlistCmd, "allowlists")
		addAliases(agentTokenCmd, "tokens")
		addAliases(agentPolicyCmd, "policies")

		// Workspace subcommands are declared as anonymous literals; resolve them.
		wsList := findSub(workspaceCmd, "list")
		wsCreate := findSub(workspaceCmd, "create")
		wsInvite := findSub(workspaceCmd, "invite")
		wsMembers := findSub(workspaceCmd, "members")
		wsRemove := findSub(workspaceCmd, "remove")
		wsPromote := findSub(workspaceCmd, "promote")
		wsDemote := findSub(workspaceCmd, "demote")
		wsDelete := findSub(workspaceCmd, "delete")

		// Layer 2: verb-noun top-level shortcuts (both numbers via aliases).
		defs := []aliasDef{
			// secrets
			{"set-secrets", []string{"set-secret"}, "set-secret(s)", secretsSetCmd, secretsCmd},
			{"list-secrets", []string{"list-secret"}, "list-secret(s)", secretsListCmd, secretsCmd},
			{"pull-secrets", []string{"pull-secret"}, "pull-secret(s)", secretsPullCmd, secretsCmd},
			{"push-secrets", []string{"push-secret"}, "push-secret(s)", secretsPushCmd, secretsCmd},
			{"delete-secrets", []string{"delete-secret", "remove-secret", "remove-secrets"}, "delete-secret(s)", secretsDeleteCmd, secretsCmd},
			{"diff-secrets", []string{"diff-secret"}, "diff-secret(s)", secretsDiffCmd, secretsCmd},

			// projects
			{"list-projects", []string{"list-project", "get-projects", "get-project"}, "list-project(s)", projectListCmd, projectCmd},
			{"create-project", []string{"create-projects"}, "create-project(s)", projectCreateCmd, projectCmd},
			{"use-project", []string{"use-projects", "link-project", "link-projects"}, "use-project(s)", projectUseCmd, projectCmd},
			{"update-project", []string{"update-projects"}, "update-project(s)", projectUpdateCmd, projectCmd},
			{"delete-project", []string{"delete-projects", "remove-project", "remove-projects"}, "delete-project(s)", projectDeleteCmd, projectCmd},
			{"invite-project", []string{"invite-projects"}, "invite-project(s)", projectInviteCmd, projectCmd},

			// workspaces
			{"list-workspaces", []string{"list-workspace", "get-workspaces", "get-workspace"}, "list-workspace(s)", wsList, workspaceCmd},
			{"switch-workspace", []string{"switch-workspaces", "use-workspace", "use-workspaces"}, "switch-workspace(s)", workspaceSwitchCmd, workspaceCmd},
			{"create-workspace", []string{"create-workspaces"}, "create-workspace(s)", wsCreate, workspaceCmd},
			{"invite-workspace", []string{"invite-workspaces"}, "invite-workspace(s)", wsInvite, workspaceCmd},
			{"list-members", []string{"list-member", "get-members", "get-member"}, "list-member(s)", wsMembers, workspaceCmd},
			{"remove-member", []string{"remove-members"}, "remove-member(s)", wsRemove, workspaceCmd},
			{"promote-member", []string{"promote-members"}, "promote-member(s)", wsPromote, workspaceCmd},
			{"demote-member", []string{"demote-members"}, "demote-member(s)", wsDemote, workspaceCmd},
			{"delete-workspace", []string{"delete-workspaces", "remove-workspace", "remove-workspaces"}, "delete-workspace(s)", wsDelete, workspaceCmd},

			// allowlist (lives under workspace; inherits workspace middleware)
			{"add-allowlist", []string{"add-allowlists", "allow-domain", "allow-domains"}, "add-allowlist(s)", allowlistAddCmd, workspaceCmd},
			{"remove-allowlist", []string{"remove-allowlists"}, "remove-allowlist(s)", allowlistRemoveCmd, workspaceCmd},
			{"list-allowlists", []string{"list-allowlist", "get-allowlists", "get-allowlist"}, "list-allowlist(s)", allowlistListCmd, workspaceCmd},
			{"get-allowlist-logs", []string{"list-allowlist-logs"}, "get-allowlist-logs", allowlistLogCmd, workspaceCmd},

			// agents
			{"list-agents", []string{"list-agent", "get-agents", "get-agent"}, "list-agent(s)", agentListCmd, agentCmd},
			{"delete-agent", []string{"delete-agents", "remove-agent", "remove-agents"}, "delete-agent(s)", agentDeleteCmd, agentCmd},
			{"issue-token", []string{"issue-tokens"}, "issue-token(s)", agentTokenIssueCmd, agentCmd},
			{"list-tokens", []string{"list-token", "get-tokens", "get-token"}, "list-token(s)", agentTokenListCmd, agentCmd},
			{"revoke-token", []string{"revoke-tokens"}, "revoke-token(s)", agentTokenRevokeCmd, agentCmd},
			{"get-agent-policy", []string{"get-agent-policies"}, "get-agent-policy", agentPolicyGetCmd, agentCmd},
			{"set-agent-policy", []string{"set-agent-policies"}, "set-agent-policy", agentPolicySetCmd, agentCmd},

			// logs
			{"list-logs", []string{"list-log", "get-logs", "get-log"}, "list-log(s)", logsCmd, logsCmd},
			{"show-log", []string{"show-logs"}, "show-log(s)", logShowCmd, logsCmd},
			{"summarize-logs", []string{"summarize-log", "summary-logs"}, "summarize-log(s)", logSummaryCmd, logsCmd},
			{"watch-logs", []string{"watch-log"}, "watch-log(s)", logWatchCmd, logsCmd},
			{"export-logs", []string{"export-log"}, "export-log(s)", logExportCmd, logsCmd},
			{"verify-logs", []string{"verify-log"}, "verify-log(s)", logVerifyCmd, logsCmd},
			{"replay-log", []string{"replay-logs"}, "replay-log(s)", logReplayCmd, logsCmd},
		}

		for _, d := range defs {
			if d.src == nil {
				continue // defensive: a source command wasn't found
			}
			rootCmd.AddCommand(mkTopAlias(d.use, d.aliases, d.src, d.group))
			shortcutDisplays = append(shortcutDisplays, [2]string{d.display, d.src.Short})
		}

		installShortcutHelp()
	})
}

// installShortcutHelp registers the "Command Shortcuts" template function and
// swaps rootCmd's usage template for one that renders that section after the
// standard "Available Commands" block. Only rootCmd's template is replaced, so
// every subcommand keeps cobra's default help layout.
func installShortcutHelp() {
	cobra.AddTemplateFunc("commandShortcuts", renderShortcuts)
	rootCmd.SetUsageTemplate(rootUsageTemplate)
}

// renderShortcuts formats the verb-noun shortcut table for the root help. The
// leading explanatory sentence tells the reader the trailing (s) is optional.
// The section is emitted only for the root command; subcommands inherit the same
// usage template (cobra walks up to the parent) but must not repeat the section,
// so a non-root command yields an empty string.
func renderShortcuts(cmd *cobra.Command) string {
	if cmd == nil || cmd.HasParent() || len(shortcutDisplays) == 0 {
		return ""
	}
	width := 0
	for _, row := range shortcutDisplays {
		if len(row[0]) > width {
			width = len(row[0])
		}
	}

	var b strings.Builder
	b.WriteString("\nCommand Shortcuts:\n")
	b.WriteString("  Verb-noun forms of the commands above. The trailing (s) is optional —\n")
	b.WriteString("  e.g. both \"list-secret\" and \"list-secrets\" work.\n\n")
	for _, row := range shortcutDisplays {
		b.WriteString(fmt.Sprintf("  %-*s  %s\n", width, row[0], row[1]))
	}
	return b.String()
}

// rootUsageTemplate is cobra's default usage template with a {{commandShortcuts}}
// call inserted immediately after the "Available Commands" section.
const rootUsageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

Available Commands:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

Additional Commands:{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{commandShortcuts .}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`
