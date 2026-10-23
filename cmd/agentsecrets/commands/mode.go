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
	Long: `Show or set the CLI-wide credential resolution mode.

	local  Resolve from the OS keychain through the local proxy. Offline, and
	       every local enforcement (allowlist, policy, SSRF, redaction, audit)
	       applies.
	cloud  Resolve through the AgentSecrets cloud resolver. Needs a workload
	       token and a billed entitlement.

	The saved mode is the default for every command that resolves credentials:
	call, env, and exec. A single command can override it with --cloud or
	--local. Precedence is flag, then AGENTSECRETS_MODE or
	AGENTSECRETS_USE_CLOUD, then the saved mode, then local.

	Examples:
	agentsecrets mode            # show the effective mode and why
	agentsecrets mode cloud      # resolve through the cloud resolver by default
	agentsecrets mode local      # go back to the local keychain`,
	Args: cobra.MaximumNArgs(1),
	RunE: runMode,
}

func runMode(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		selection, err := gateway.Select("")
		if err != nil {
			return err
		}
		stored := config.GetDefaultMode()
		if stored == "" {
			stored = "(not set)"
		}
		ui.StatusRow("Mode:", string(selection.Mode))
		ui.StatusRow("Selected by:", selection.Source)
		ui.StatusRow("Saved mode:", stored)
		if selection.Mode == gateway.ModeCloud && gateway.TokenFromEnv() == "" {
			ui.Warning("Cloud mode is selected but no workload token is set. Set AGENTSECRETS_TOKEN or AGENTSECRETS_TOKEN_FILE.")
		}
		return nil
	}

	mode := args[0]
	if mode != string(gateway.ModeLocal) && mode != string(gateway.ModeCloud) {
		return fmt.Errorf("mode must be %q or %q, got %q", gateway.ModeLocal, gateway.ModeCloud, mode)
	}
	if err := config.SetDefaultMode(mode); err != nil {
		return err
	}
	ui.Success("Saved mode: " + mode)
	if mode == string(gateway.ModeCloud) && gateway.TokenFromEnv() == "" {
		ui.Warning("No workload token is set yet. Cloud resolution needs AGENTSECRETS_TOKEN or AGENTSECRETS_TOKEN_FILE.")
	}
	return nil
}
