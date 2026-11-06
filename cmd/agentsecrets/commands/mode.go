package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/gateway"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var modeCmd = &cobra.Command{
	Use:   "mode [local|cloud]",
	Short: "Show or set where the CLI resolves credentials",
	Long: `Show or set the credential resolution mode.

	local  Resolve from the OS keychain through the local proxy. Offline, and
	       every local enforcement (allowlist, policy, SSRF, redaction, audit)
	       applies.
	cloud  Resolve through the AgentSecrets cloud resolver. Needs a workload
	       token and a billed entitlement.

Without --project the choice is global, so every project resolves the same
way. With --project it is saved in .agentsecrets/project.json and applies only
to this project; that lets one project run in cloud while the rest stay local.

Precedence, highest first: an explicit --cloud/--local flag (one request
only), then AGENTSECRETS_MODE or AGENTSECRETS_USE_CLOUD, then the project mode,
then the global mode, then a workload token in the environment, then local.

Examples:
	agentsecrets mode                    # show the effective mode and why
	agentsecrets mode cloud              # resolve through the cloud resolver everywhere
	agentsecrets mode cloud --project    # resolve through the cloud resolver only here
	agentsecrets mode local              # go back to the local keychain`,
	Args: cobra.MaximumNArgs(1),
	RunE: runMode,
}

func init() {
	modeCmd.Flags().Bool("project", false, "save the mode in this project's config instead of the global config")
}

func runMode(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		selection, err := gateway.Select("")
		if err != nil {
			return err
		}
		global := config.GetDefaultMode()
		if global == "" {
			global = "(not set)"
		}
		project := config.GetProjectMode()
		if project == "" {
			project = "(not set)"
		}
		ui.StatusRow("Mode:", string(selection.Mode))
		ui.StatusRow("Selected by:", selection.Source)
		ui.StatusRow("Global mode:", global)
		ui.StatusRow("Project mode:", project)
		if selection.Mode == gateway.ModeCloud && gateway.TokenFromEnv() == "" {
			ui.Warning("Cloud mode is selected but no workload token is set. Set AGENTSECRETS_TOKEN or AGENTSECRETS_TOKEN_FILE.")
		}
		return nil
	}

	mode := args[0]
	if mode != string(gateway.ModeLocal) && mode != string(gateway.ModeCloud) {
		return fmt.Errorf("mode must be %q or %q, got %q", gateway.ModeLocal, gateway.ModeCloud, mode)
	}

	projectScope, _ := cmd.Flags().GetBool("project")
	if projectScope {
		if err := config.SetProjectMode(mode); err != nil {
			return err
		}
		ui.Success("Saved project mode: " + mode)
	} else {
		if err := config.SetDefaultMode(mode); err != nil {
			return err
		}
		ui.Success("Saved global mode: " + mode)
	}

	if mode == string(gateway.ModeCloud) && gateway.TokenFromEnv() == "" {
		ui.Warning("No workload token is set yet. Cloud resolution needs AGENTSECRETS_TOKEN or AGENTSECRETS_TOKEN_FILE.")
	}
	return nil
}
