package commands

import (
	"fmt"

	"github.com/charmbracelet/huh"

	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/ui"
)

// showRecoveryKey prints a one-time key and asks the user to confirm they saved
// it. It returns true only when the user explicitly confirms.
func showRecoveryKey(key string) bool {
	fmt.Println()
	ui.Warning("Save this recovery key. It is shown once and is never stored on this device.")
	fmt.Println()
	fmt.Printf("  %s\n", key)
	fmt.Println()

	var saved bool
	if err := huh.NewConfirm().
		Title("I have saved the recovery key").
		Description("Without the key and your password, this account cannot be recovered.").
		Value(&saved).
		Run(); err != nil {
		return false
	}
	return saved
}

// showVaultResult prints non-fatal vault warnings and, when a new vault was
// created, shows the one-time recovery key and offers to confirm it. It reports
// whether the recovery key was confirmed during this call.
func showVaultResult(result *auth.LoginResult, password string) bool {
	if result == nil {
		return false
	}
	for _, warning := range result.Warnings {
		ui.Warning(warning)
	}
	if result.RecoveryKey == "" {
		return false
	}
	if !showRecoveryKey(result.RecoveryKey) {
		ui.Warning("Recovery not confirmed. Rotate a new key later with 'agentsecrets vault recovery rotate'.")
		return false
	}

	if err := app.Auth().ConfirmRecovery(password); err != nil {
		ui.Warning(fmt.Sprintf("Could not confirm recovery: %v", err))
		return false
	}
	ui.Success("Recovery key confirmed.")
	return true
}
