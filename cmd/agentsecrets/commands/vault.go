package commands

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Inspect and rotate the account vault",
}

var vaultStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show vault envelopes and recovery state",
	RunE: func(cmd *cobra.Command, args []string) error {
		status, err := app.Auth().VaultStatus()
		if err != nil {
			ui.Error(fmt.Sprintf("Vault status failed: %v", err))
			return nil
		}
		if !status.Supported {
			ui.Info("This server does not support vault storage yet.")
			return nil
		}
		if status.Version == 0 {
			ui.Info("No vault on this account yet. Run 'agentsecrets login' to migrate.")
			return nil
		}
		fmt.Printf("Vault version: %d\n", status.Version)
		fmt.Printf("Envelopes: %s\n", strings.Join(status.Envelopes, ", "))
		if status.Confirmed {
			fmt.Println("Recovery key: confirmed")
		} else {
			fmt.Println("Recovery key: not confirmed")
		}
		return nil
	},
}

var vaultRecoveryCmd = &cobra.Command{
	Use:   "recovery",
	Short: "Manage the recovery key",
}

var vaultRecoveryRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Create a new recovery key and retire the old one",
	Long: `Create a new recovery key.

The new key is added first and the old key stays valid until you confirm that
you saved the new one. If you abort or the process crashes, no lockout occurs.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var password string
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Account password").
					EchoMode(huh.EchoModePassword).
					Value(&password).
					Validate(func(s string) error {
						if s == "" {
							return fmt.Errorf("password is required")
						}
						return nil
					}),
			),
		)
		if err := form.Run(); err != nil {
			return nil
		}

		var rotation *auth.RecoveryRotation
		pendingEnvelope, _ := config.GetPendingRecovery()
		spinnerLabel := "Creating a new recovery key..."
		if pendingEnvelope != "" {
			spinnerLabel = "Resuming the interrupted recovery key rotation..."
		}
		if err := ui.Spinner(spinnerLabel, func() error {
			var err error
			if pendingEnvelope != "" {
				rotation, err = app.Auth().ResumeRecoveryRotation(password)
				return err
			}
			rotation, err = app.Auth().BeginRecoveryRotation(password)
			if err == nil {
				if markerErr := config.SetPendingRecovery(rotation.EnvelopeID, rotation.Version); markerErr != nil {
					return fmt.Errorf("recovery key created but the resume marker could not be saved: %w", markerErr)
				}
			}
			return err
		}); err != nil {
			return err
		}

		if !showRecoveryKey(rotation.Key) {
			ui.Warning("New key not confirmed. The old key is still valid. Run this command again to resume the rotation with the same envelope.")
			return nil
		}

		if err := ui.Spinner("Retiring the old recovery key...", func() error {
			return app.Auth().FinishRecoveryRotation(rotation)
		}); err != nil {
			return err
		}
		if err := config.ClearPendingRecovery(); err != nil {
			return fmt.Errorf("recovery key rotated but the resume marker could not be cleared: %w", err)
		}
		ui.Success("Recovery key rotated. The old key no longer works.")
		return nil
	},
}

func init() {
	vaultRecoveryCmd.AddCommand(vaultRecoveryRotateCmd)
	vaultCmd.AddCommand(vaultStatusCmd, vaultRecoveryCmd)
}
