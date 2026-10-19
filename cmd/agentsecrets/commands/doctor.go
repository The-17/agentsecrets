package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/keychainauth"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var (
	doctorCheckOnly bool
	doctorJSON      bool
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose and repair your AgentSecrets installation",
	Long: `Check that AgentSecrets can securely reach your secrets, and repair it if not.

The doctor verifies every part of the local trust chain:
  - keychain-auth is installed and up to date
  - the daemon is running and reachable
  - the running daemon is not serving outdated code
  - this AgentSecrets binary is authorized (path + SHA-256)
  - the daemon's live policy actually grants this binary access
  - the trust store is not writable by other users
  - your stored credentials are readable

Anything it can fix safely, it fixes — then re-checks to prove the fix worked.

The doctor cannot grant itself access. Authorizing a binary is still performed by
keychain-auth, still requires administrator rights on a system-mode install, and
only ever applies to this exact binary.`,
	RunE: runDoctor,
}

func init() {
	doctorCmd.Flags().BoolVar(&doctorCheckOnly, "check-only", false, "Report problems without repairing anything")
	doctorCmd.Flags().BoolVar(&doctorJSON, "json", false, "Emit the report as JSON")
	rootCmd.AddCommand(doctorCmd)
}

// runDoctor deliberately has no keychain-auth middleware: it must run when the
// daemon is broken, which is precisely when that middleware would fail.
func runDoctor(cmd *cobra.Command, args []string) error {
	report := keychainauth.Diagnose()

	if !doctorCheckOnly && !report.Healthy() {
		if report.NeedsSudo() {
			ensureSudoCached("Repairing keychain-auth requires your password.")
		}
		report = report.Repair(func(label string, fn func() error) error {
			if doctorJSON {
				return fn()
			}
			return ui.Spinner(label, fn)
		})
	}

	if doctorJSON {
		return emitDoctorJSON(report)
	}

	renderDoctorReport(report)

	if !report.Healthy() {
		// Non-zero exit so scripts and CI can gate on a broken installation.
		return &ExitError{Code: 1, Silent: true}
	}
	return nil
}

func renderDoctorReport(report *keychainauth.Report) {
	fmt.Println()
	ui.Banner("AgentSecrets Doctor")
	ui.Divider()

	ui.StatusRow("Platform", doctorPlatformLabel(report.Platform))
	if report.KeychainAuthPath != "" {
		version := report.DaemonVersion
		if version == "" {
			version = "unknown"
		}
		ui.StatusRow("keychain-auth", fmt.Sprintf("%s (%s)", version, report.KeychainAuthPath))
	}
	if report.DaemonMode != "" {
		ui.StatusRow("Daemon mode", report.DaemonMode)
	}
	if report.SocketPath != "" {
		ui.StatusRow("Socket", report.SocketPath)
	}
	if report.SelfPath != "" {
		ui.StatusRow("This binary", report.SelfPath)
	}

	fmt.Println()
	for _, f := range report.Findings {
		fmt.Printf("%s %s\n", doctorStatusGlyph(f.Status), f.Title)
		if f.Detail != "" {
			fmt.Println(ui.DimStyle.Render("    " + f.Detail))
		}
		if f.Remedy != "" {
			fmt.Println(ui.DimStyle.Render("    → " + f.Remedy))
		}
	}

	fmt.Println()
	if report.Healthy() {
		ui.Success("AgentSecrets is healthy.")
		return
	}

	ui.Error("AgentSecrets is not able to reach your secrets.")
	for _, f := range report.Broken() {
		if !f.Fixable() && f.Remedy == "" {
			ui.Info("  " + f.Title + ": " + f.Detail)
		}
	}
	if doctorCheckOnly {
		ui.Info("Re-run 'agentsecrets doctor' without --check-only to repair.")
	}
}

func doctorPlatformLabel(p keychainauth.Platform) string {
	label := p.OS
	switch {
	case p.IsWSL:
		label += " (WSL)"
	case p.OS == "linux" && !p.HasSystemd:
		label += " (no systemd)"
	}
	return label
}

func doctorStatusGlyph(s keychainauth.Status) string {
	switch s {
	case keychainauth.StatusOK:
		return ui.SuccessStyle.Render("✓")
	case keychainauth.StatusWarn:
		return ui.WarningStyle.Render("!")
	case keychainauth.StatusBroken:
		return ui.ErrorStyle.Render("x")
	default:
		return ui.DimStyle.Render("-")
	}
}

// emitDoctorJSON writes a machine-readable report for scripts and support triage.
func emitDoctorJSON(report *keychainauth.Report) error {
	type findingJSON struct {
		ID      string `json:"id"`
		Title   string `json:"title"`
		Status  string `json:"status"`
		Detail  string `json:"detail,omitempty"`
		Remedy  string `json:"remedy,omitempty"`
		Fixable bool   `json:"fixable"`
	}
	out := struct {
		Healthy          bool          `json:"healthy"`
		OS               string        `json:"os"`
		IsWSL            bool          `json:"is_wsl"`
		HasSystemd       bool          `json:"has_systemd"`
		KeychainAuthPath string        `json:"keychain_auth_path,omitempty"`
		DaemonVersion    string        `json:"daemon_version,omitempty"`
		DaemonMode       string        `json:"daemon_mode,omitempty"`
		SocketPath       string        `json:"socket_path,omitempty"`
		SelfPath         string        `json:"self_path,omitempty"`
		Findings         []findingJSON `json:"findings"`
	}{
		Healthy:          report.Healthy(),
		OS:               report.Platform.OS,
		IsWSL:            report.Platform.IsWSL,
		HasSystemd:       report.Platform.HasSystemd,
		KeychainAuthPath: report.KeychainAuthPath,
		DaemonVersion:    report.DaemonVersion,
		DaemonMode:       report.DaemonMode,
		SocketPath:       report.SocketPath,
		SelfPath:         report.SelfPath,
	}
	for _, f := range report.Findings {
		out.Findings = append(out.Findings, findingJSON{
			ID:      f.ID,
			Title:   f.Title,
			Status:  f.Status.String(),
			Detail:  f.Detail,
			Remedy:  f.Remedy,
			Fixable: f.Fixable(),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encode doctor report: %w", err)
	}
	if !report.Healthy() {
		return &ExitError{Code: 1, Silent: true}
	}
	return nil
}
