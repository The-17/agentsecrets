package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Show your account card (identity, vault, key)",
	RunE: func(cmd *cobra.Command, args []string) error {
		email := config.GetEmail()
		if email == "" {
			ui.Error("not logged in; run 'agentsecrets login' first")
			return nil
		}

		host := config.GetServerURL()
		if host == "" {
			host = "(unknown host)"
		}

		// Key fingerprint is an audit anchor: sha256 of the account public key.
		fingerprint := "(no key in store)"
		if pub, err := keyring.GetPublicKey(email); err == nil && len(pub) > 0 {
			h := sha256.Sum256(pub)
			hexed := hex.EncodeToString(h[:])
			fingerprint = "sha256:" + hexed[:8] + "…" + hexed[len(hexed)-4:]
		}

		vs, err := app.Auth().VaultStatus()
		if err != nil {
			ui.Error(fmt.Sprintf("could not read vault status: %s", err))
			return nil
		}

		var vaultLine string
		switch {
		case !vs.Supported:
			vaultLine = "not supported on this server"
		case vs.Version == 0 || len(vs.Envelopes) == 0:
			vaultLine = "no vault yet"
		default:
			vaultLine = fmt.Sprintf("v%d · %s", vs.Version, strings.Join(vs.Envelopes, ", "))
		}
		recoveryLine := "not confirmed"
		if vs.Confirmed {
			recoveryLine = "confirmed"
		}

		printAccountCard(email, host, fingerprint, vaultLine, recoveryLine)
		return nil
	},
}

// printAccountCard draws a lean ASCII card. It intentionally shows only account
// facts (identity, vault, key) and never duplicates the system-health output of
// the status command.
func printAccountCard(email, host, fingerprint, vaultLine, recoveryLine string) {
	rows := []struct{ label, value string }{
		{"email", email},
		{"host", host},
		{"key", fingerprint},
		{"vault", vaultLine},
		{"recovery key", recoveryLine},
	}

	width := 0
	for _, r := range rows {
		if l := len(r.label) + 2 + len(r.value); l > width {
			width = l
		}
	}
	if width < 22 {
		width = 22
	}
	rule := "─" + strings.Repeat("─", width+2) + "─"

	fmt.Println("┌" + rule + "┐")
	for _, r := range rows {
		pad := width - len(r.label) - len(r.value)
		if pad < 0 {
			pad = 0
		}
		fmt.Printf("│ %s%s%s%s │\n", r.label, strings.Repeat(" ", 2), strings.Repeat(" ", pad), r.value)
	}
	fmt.Println("└" + rule + "┘")
}
