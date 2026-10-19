package commands

import (
	"fmt"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current session and project info",
	Long: `Show the current AgentSecrets session status.

	Displays:
	- CLI version and update status
	- Whether you're logged in
	- Your email
	- Active workspace
	- Current project (if in a project directory)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println()
		ui.Banner("AgentSecrets Status")
		ui.Divider()

		global, _ := config.LoadGlobalConfig()

		// Auth status
		isAuthenticated := config.IsAuthenticated()
		if isAuthenticated {
			email := config.GetEmail()
			ui.StatusRow("Logged in as:", email)

			// Token Health
			tokens, _ := config.LoadTokens()
			if tokens != nil {
				// Check Access Token
				if tokens.ExpiresAt != "" {
					exp, err := time.Parse(time.RFC3339, tokens.ExpiresAt)
					if err == nil {
						timeUntil := time.Until(exp)
						if timeUntil <= 0 {
							if tokens.RefreshToken != "" {
								ui.StatusRow("Session:", "Expired — will auto-refresh on next command")
							} else {
								ui.StatusRow("Session:", "Expired — run 'agentsecrets login'")
							}
						} else if timeUntil < 5*time.Minute {
							// e.g., "in 3 minutes" -> "3 minutes" by stripping "in "
							timeLeft := humanize.Time(exp)
							if strings.HasPrefix(timeLeft, "in ") {
								timeLeft = timeLeft[3:]
							}
							ui.StatusRow("Session:", fmt.Sprintf("Expiring Soon (%s left) — will auto-refresh on next command", timeLeft))
						} else {
							ui.StatusRow("Session:", fmt.Sprintf("Active (expires %s)", humanize.Time(exp)))
						}
					} else {
						ui.StatusRowDim("Session:", "Unknown expiry")
					}
				} else {
					ui.StatusRowDim("Session:", "Unknown expiry")
				}

				// Check Refresh Token
				if tokens.RefreshToken != "" {
					ui.StatusRow("Refresh Token:", "Available")
				} else {
					ui.StatusRow("Refresh Token:", "Missing")
				}
			}

			// Workspace info
			wsID := config.GetSelectedWorkspaceID()

			wsDisplay := "—"
			wsDim := true
			if wsID != "" && global != nil {
				if ws, ok := global.Workspaces[wsID]; ok {
					wsDisplay = fmt.Sprintf("%s (%s)", ws.Name, ws.Type)
					wsDim = false
				} else {
					wsDisplay = wsID
					wsDim = false
				}
			}

			if wsDim {
				ui.StatusRowDim("Selected Workspace:", wsDisplay)
			} else {
				ui.StatusRow("Selected Workspace:", wsDisplay)
			}
		} else {
			ui.StatusRowDim("Logged in:", "No")
		}

		// Server target info
		target := config.ResolveServerTarget("")
		serverType := "AgentSecrets Server (Default)"
		if target.IsSelfHost {
			serverType = ui.BrandStyle.Render("Self-Hosted Server (Custom URL)")
		}
		ui.StatusRow("Server:", fmt.Sprintf("%s (%s)", target.URL, serverType))

		// Environment info
		env, source := config.ResolveEnvironmentWithSource()
		envDisplay := fmt.Sprintf("%s (from %s)", env, source)
		ui.StatusRow("Environment:", envDisplay)
		p, err := config.LoadProjectConfig()
		if err == nil && p.ProjectName != "" {
			workspaceName := p.WorkspaceName
			if workspaceName == "" && global != nil {
				if ws, ok := global.Workspaces[p.WorkspaceID]; ok {
					workspaceName = ws.Name
				}
			}

			projectDisplay := p.ProjectName
			if workspaceName != "" {
				projectDisplay += fmt.Sprintf(" (in %s)", workspaceName)
			}
			ui.StatusRow("Current Project:", projectDisplay)

			// Sync info
			secretsDisplay := "Unable to calculate"
			if !isAuthenticated {
				secretsDisplay = "Login to view"
			} else {
				diff, diffErr := app.Secrets().DiffCached("", "")
				if diffErr != nil {
					secretsDisplay = fmt.Sprintf("Could not check (%s)", diffErr.Error())
				} else {
					syncedCount := len(diff.Unchanged)
					unsyncedCount := len(diff.Added) + len(diff.Changed) + len(diff.Removed)
					total := syncedCount + unsyncedCount
					if total == 0 {
						secretsDisplay = "No secrets found"
					} else {
						secretsDisplay = fmt.Sprintf("%d synced (%d unsynced)", syncedCount, unsyncedCount)
					}
				}
			}
			ui.StatusRow("Secrets:", secretsDisplay)

			// Proxy status
			if pid, port, running := proxy.IsProxyRunning(); running {
				ui.StatusRow("Proxy:", fmt.Sprintf("Running (port %d, PID %d)", port, pid))
			} else {
				ui.StatusRowDim("Proxy:", "Not running")
			}

			ui.StatusRow("Activity:", fmt.Sprintf("Last Push: %s | Last Pull: %s", formatTime(p.LastPush), formatTime(p.LastPull)))
		} else {
			ui.StatusRowDim("Current Project:", "—")
		}

		// CLI version, annotated with the cached update verdict. The update
		// check runs in the root preamble, so this is a cache read.
		latest := ""
		if global != nil {
			latest = global.LatestVersion
		}
		ui.StatusRow("Version:", statusVersionDisplay(Version, latest))

		fmt.Println()
		return nil
	},
}

// statusVersionDisplay renders the CLI version alongside its cached update
// verdict, for example "4.0.0-dev (dev build)".
func statusVersionDisplay(current, latest string) string {
	if verdict := config.VersionStatus(current, latest); verdict != "" {
		return fmt.Sprintf("%s (%s)", current, verdict)
	}
	return current
}

func formatTime(rfc3339Str string) string {
	if rfc3339Str == "" {
		return "Never"
	}
	t, err := time.Parse(time.RFC3339, rfc3339Str)
	if err != nil {
		return rfc3339Str
	}
	return humanize.Time(t)
}
