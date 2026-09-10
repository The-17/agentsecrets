package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/log"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var (
	proxyPort      int
	logsSecretFlag string
	logsLastFlag   int
	logsEnvFlag    string
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Manage the AgentSecrets credentialed proxy",
	Long:  `Start, stop, and monitor the HTTP proxy that lets AI agents make authenticated API calls without seeing credential values.`,
}

var proxyStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the proxy server",
	Long:  `Start the HTTP proxy on localhost. AI agents send requests here with X-AS-* headers; the proxy injects real credentials and forwards to the target API.`,
	RunE:  runProxyStart,
}

var proxyStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check if the proxy is running",
	RunE:  runProxyStatus,
}

var proxyStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running proxy server",
	RunE:  runProxyStop,
}

var proxySyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Force an immediate revocation list sync",
	RunE:  runProxySync,
}

var proxyLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "View proxy audit log",
	Long:  `View the audit log of API calls made through the proxy. Shows secret key names, target URLs, and response codes. Never shows secret values.`,
	RunE:  runProxyLogs,
}

var proxyApproveCmd = &cobra.Command{
	Use:   "approve <SECRET_KEY> <METHOD> <DOMAIN>",
	Short: "Grant a session-based approval for a policy-restricted secret",
	Long: `When a secret's policy is set to 'request_permission' for a specific domain/method
combination, the proxy blocks the request until the developer explicitly approves it.

This command sends the approval to the running proxy. The approval lasts for the
current proxy session (until the proxy is restarted).

Example:
  agentsecrets proxy approve STRIPE_KEY POST api.stripe.com`,
	Args: cobra.ExactArgs(3),
	RunE: runProxyApprove,
}

func init() {
	proxyStartCmd.Flags().IntVar(&proxyPort, "port", 8765, "Port to listen on")

	proxyLogsCmd.Flags().StringVar(&logsSecretFlag, "secret", "", "Filter logs by secret key name")
	proxyLogsCmd.Flags().IntVar(&logsLastFlag, "last", 20, "Number of recent log entries to show")
	proxyLogsCmd.Flags().StringVar(&logsEnvFlag, "env", "", "Filter logs by environment (development, staging, production)")

	proxyStartCmd.PreRunE = keychainAuthMiddleware
	proxySyncCmd.PreRunE = keychainAuthMiddleware
	proxyLogsCmd.PreRunE = keychainAuthMiddleware

	proxyCmd.AddCommand(proxyStartCmd)
	proxyCmd.AddCommand(proxyStatusCmd)
	proxyCmd.AddCommand(proxyStopCmd)
	proxyCmd.AddCommand(proxySyncCmd)
	proxyCmd.AddCommand(proxyLogsCmd)
	proxyCmd.AddCommand(proxyApproveCmd)
	proxyCmd.AddCommand(proxyRotateSessionCmd)
}

// Uptime format helper remains here.

// formatUptime returns a human-readable uptime string from a start time.
func formatUptime(start time.Time) string {
	d := time.Since(start)
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, int(d.Seconds())%60)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

func runProxyStart(cmd *cobra.Command, args []string) error {
	fmt.Println()
	ui.Banner("AgentSecrets Proxy")
	ui.Divider()

	// Load project context
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		ui.ErrorWithSuggestions(
			fmt.Errorf("No active project link found in the current directory"),
			"Run 'agentsecrets project use' to select and link an existing project.",
			"Run 'agentsecrets project create <name>' to create and link a new project.",
		)
		return nil
	}

	ui.StatusRow("Project:", project.ProjectName)
	ui.StatusRow("Port:", fmt.Sprintf("%d", proxyPort))
	fmt.Println()

	engine, err := proxy.NewEngine(project.ProjectID)
	if err != nil {
		ui.ErrorWithSuggestions(
			fmt.Errorf("Failed to initialize proxy engine: %w", err),
			"Verify that your local credentials and workspace keys are synced: 'agentsecrets secrets pull'.",
			"Check if there are conflicts in your local configuration or storage.",
		)
		return nil
	}

	// Inject the shared API client for cloud log syncing
	if engine.Audit != nil {
		engine.Audit.APIClient = app.API()
	}

	agentToken := os.Getenv("AS_AGENT_TOKEN")
	if agentToken != "" {
		ui.StatusRow("Agent:", "Token provided via AS_AGENT_TOKEN (issued)")
	} else {
		ui.StatusRowDim("Agent:", "(none — calls will be logged as anonymous)")
	}

	// Generate and write pre-shared session token to Keychain
	sessionToken, err := proxy.GenerateSessionToken()
	if err != nil {
		ui.Error(fmt.Sprintf("Failed to generate session token: %v", err))
		return nil
	}
	if err := proxy.WriteSessionToken(sessionToken); err != nil {
		ui.Error(fmt.Sprintf("Failed to store session token securely in Keychain: %v", err))
		return nil
	}
	ui.StatusRow("Session Token:", "Active (secured in OS Keychain)")

	server := proxy.NewServer(proxyPort, engine)
	server.SetSessionToken(sessionToken)

	// Write PID file for proxy status
	if err := proxy.WritePIDFile(proxyPort); err != nil {
		ui.Warning(fmt.Sprintf("Failed to write PID file: %v", err))
	}
	defer proxy.RemovePIDFile()

	ui.Success(fmt.Sprintf("\nProxy listening on http://localhost:%d/proxy", proxyPort))
	ui.Info("Press Ctrl+C to stop")
	fmt.Println()

	// Wire up interactive approval prompts in this terminal.
	// When a request is blocked waiting for approval, this goroutine fires
	// immediately and shows a y/N prompt — no timeout, no polling.
	startInteractiveApprovalLoop(engine)

	// Cancel on SIGINT/SIGTERM so Start performs a graceful shutdown and the
	// deferred cleanup (PID file removal, audit flush) actually runs — a hard
	// Ctrl+C kill would skip the defers and leave a stale PID file behind.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return server.Start(ctx)
}

func runProxyStatus(cmd *cobra.Command, args []string) error {
	fmt.Println()
	ui.Banner("Proxy Status")
	ui.Divider()

	// Read PID file for running state
	pid, startTime, port, err := proxy.ReadPIDFile()
	if err != nil {
		ui.StatusRow("Proxy status:", ui.ErrorStyle.Render("not running"))
	} else if !proxy.IsProcessAlive(pid) {
		ui.StatusRow("Proxy status:", ui.ErrorStyle.Render("not running"))
		ui.StatusRowDim("Last PID:", fmt.Sprintf("%d (exited)", pid))
		proxy.RemovePIDFile()
	} else {
		// Verify port is actively listening
		conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if dialErr != nil {
			ui.StatusRow("Proxy status:", ui.ErrorStyle.Render("not running"))
			ui.StatusRowDim("Last PID:", fmt.Sprintf("%d (port %d unreachable)", pid, port))
			proxy.RemovePIDFile()
		} else {
			conn.Close()
			ui.StatusRow("Proxy status:", ui.SuccessStyle.Render("running"))
			ui.StatusRow("PID:", fmt.Sprintf("%d", pid))
			ui.StatusRow("Port:", fmt.Sprintf("%d", port))
			ui.StatusRow("Uptime:", formatUptime(startTime))

			// Try to fetch live metrics from /health
			healthURL := fmt.Sprintf("http://localhost:%d/health", port)
			client := &http.Client{Timeout: 1 * time.Second}
			resp, err := client.Get(healthURL)
			if err == nil {
				defer resp.Body.Close()
				var health struct {
					LastSync     string   `json:"last_sync"`
					RevokedCount int      `json:"revoked_count"`
					RevokedIDs   []string `json:"revoked_ids"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&health); err == nil {
					syncVal := "never"
					if t, err := time.Parse(time.RFC3339, health.LastSync); err == nil && !t.IsZero() {
						syncVal = formatUptime(t) + " ago"
					}
					ui.StatusRow("Last sync:", syncVal)
					if health.RevokedCount > 0 {
						ui.StatusRow("Revoked IDs:", fmt.Sprintf("%d (%s)", health.RevokedCount, strings.Join(health.RevokedIDs, ", ")))
					} else {
						ui.StatusRow("Revoked IDs:", "0")
					}
				} else {
					ui.StatusRowDim("Last sync:", "(failed to parse health data)")
					ui.StatusRowDim("Revoked IDs:", "(failed to parse health data)")
				}
			} else {
				ui.StatusRowDim("Last sync:", "(proxy unreachable for status check)")
				ui.StatusRowDim("Revoked IDs:", "(proxy unreachable for status check)")
			}
		}
	}

	fmt.Println()

	// Check the audit database file
	logPath, err := proxy.DefaultLogPath()
	if err != nil {
		ui.StatusRowDim("Audit DB:", "Not found")
	} else {
		info, err := os.Stat(logPath)
		if err != nil {
			ui.StatusRowDim("Audit DB:", "No audit database yet")
		} else {
			ui.StatusRow("Audit DB:", logPath)
			ui.StatusRow("Size:", fmt.Sprintf("%d bytes", info.Size()))
			ui.StatusRow("Last modified:", info.ModTime().Format(time.RFC3339))
		}
	}

	fmt.Println()
	ui.Info("To start the proxy: agentsecrets proxy start")
	fmt.Println()
	return nil
}

func runProxyStop(cmd *cobra.Command, args []string) error {
	pid, _, _, err := proxy.ReadPIDFile()
	if err != nil {
		ui.Info("No running proxy found (no PID file).")
		return nil
	}

	if !proxy.IsProcessAlive(pid) {
		ui.Info(fmt.Sprintf("Proxy process %d is already dead.", pid))
		proxy.RemovePIDFile()
		return nil
	}

	ui.Info(fmt.Sprintf("Stopping proxy (PID %d)...", pid))
	p, _ := os.FindProcess(pid)
	if err := p.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to send SIGTERM to proxy: %w", err)
	}

	// Wait up to 5 seconds for it to stop
	for i := 0; i < 50; i++ {
		if !proxy.IsProcessAlive(pid) {
			proxy.RemovePIDFile()
			ui.Success("Proxy stopped.")
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Try SIGKILL if still alive
	ui.Warning("Proxy didn't stop with SIGTERM, sending SIGKILL...")
	if err := p.Kill(); err != nil {
		return fmt.Errorf("failed to kill proxy: %w", err)
	}
	proxy.RemovePIDFile()
	ui.Success("Proxy force-killed.")
	return nil
}

func runProxySync(cmd *cobra.Command, args []string) error {
	// Determine port from PID file or default
	port := 8765
	_, _, pidPort, err := proxy.ReadPIDFile()
	if err == nil && pidPort > 0 {
		port = pidPort
	}

	url := fmt.Sprintf("http://localhost:%d/sync", port)
	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	sessionToken, _ := proxy.ReadSessionToken()
	if sessionToken != "" {
		req.Header.Set("X-AS-Session-Token", sessionToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("proxy not reachable on port %d: %w", port, err)
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("invalid response from proxy: %w", err)
	}

	if result["status"] == "ok" {
		ui.Success("Revocation sync triggered successfully.")
	} else {
		ui.Warning("Sync request returned unexpected status.")
	}
	return nil
}

func runProxyLogs(cmd *cobra.Command, args []string) error {
	fmt.Println()
	ui.Banner("Proxy Audit Log")

	// Query the SQLite audit database
	svc, err := log.NewService(nil, nil)
	if err != nil {
		ui.Info("No audit log found. The proxy hasn't been used yet.")
		fmt.Println()
		return nil
	}
	defer svc.Close()

	filter := log.Filter{
		Limit:             logsLastFlag,
		ExcludeManagement: true,
	}
	if logsSecretFlag != "" {
		filter.Credential = logsSecretFlag
	}

	events, err := svc.QueryLocal(filter)
	if err != nil {
		return fmt.Errorf("failed to query audit log: %w", err)
	}

	if len(events) == 0 {
		if logsSecretFlag != "" {
			ui.Info(fmt.Sprintf("No log entries found for secret %q", logsSecretFlag))
		} else {
			ui.Info("No log entries found. The proxy hasn't been used yet.")
		}
		fmt.Println()
		return nil
	}

	// Display as table (events come back newest-first from QueryLocal)
	headers := []string{"Time", "Status", "Method", "Target URL", "Secrets", "Auth", "Code", "Reason", "Duration"}
	rows := make([][]string, len(events))
	for i, e := range events {
		targetURL := e.TargetURL
		targetURL = strings.TrimPrefix(targetURL, "https://")
		targetURL = strings.TrimPrefix(targetURL, "http://")
		if len(targetURL) > 30 {
			targetURL = targetURL[:27] + "..."
		}

		statusStr := e.Status
		if statusStr == "BLOCKED" {
			statusStr = ui.ErrorStyle.Render("x BLOCK")
		} else if statusStr == "OK" {
			statusStr = ui.SuccessStyle.Render("* OK")
		} else {
			statusStr = "* OK" // backward compat for old logs
		}

		reasonStr := e.Reason
		if reasonStr == "" {
			reasonStr = "-"
		}
		if e.Redacted {
			statusStr += " " + ui.ErrorStyle.Render("(REDACTED)")
		}

		rows[i] = []string{
			e.Timestamp.Format("15:04:05"),
			statusStr,
			e.Method,
			targetURL,
			strings.Join(e.SecretKeys, ", "),
			strings.Join(e.AuthStyles, ", "),
			fmt.Sprintf("%d", e.StatusCode),
			reasonStr,
			fmt.Sprintf("%dms", e.DurationMs),
		}
	}

	table := ui.RenderTable(headers, rows)
	fmt.Printf("%s\n", table)

	ui.Info(fmt.Sprintf("Showing %d entries", len(events)))
	fmt.Println()
	return nil
}

func runProxyApprove(cmd *cobra.Command, args []string) error {
	secretKey := strings.ToUpper(args[0])
	method := strings.ToUpper(args[1])
	domain := strings.ToLower(args[2])

	// Read PID file to determine running proxy port
	_, _, port, err := proxy.ReadPIDFile()
	if err != nil {
		return fmt.Errorf("proxy does not appear to be running — start it first with 'agentsecrets proxy start'")
	}

	payload := map[string]string{
		"secret_key": secretKey,
		"method":     method,
		"domain":     domain,
	}
	body, _ := json.Marshal(payload)

	url := fmt.Sprintf("http://localhost:%d/approve", port)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	sessionToken, _ := proxy.ReadSessionToken()
	if sessionToken != "" {
		req.Header.Set("X-AS-Session-Token", sessionToken)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to reach proxy at %s — is it running?", url)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("approval failed: %s", string(respBody))
	}

	ui.Success(fmt.Sprintf("Approved: %s can be used for %s requests to %s (this session only)", secretKey, method, domain))
	return nil
}

// startInteractiveApprovalLoop runs in the background while the proxy is active.
// It reads from engine.Approvals.Notifications(), which fires immediately the
// moment a request goroutine calls WaitForApproval. The goroutine prints a
// formatted prompt right away so the developer can approve without leaving the
// proxy terminal — and without any polling or timeout expiry first.
//
// This is a no-op when not attached to an interactive terminal (CI/headless).
func startInteractiveApprovalLoop(engine *proxy.Engine) {
	if engine.Approvals == nil {
		return
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		// Headless / piped — /approve endpoint is the only path.
		return
	}

	go func() {
		// Track keys we're already prompting for to avoid duplicate prompts
		// when multiple requests for the same key arrive simultaneously.
		handling := make(map[proxy.ApprovalKey]bool)

		for key := range engine.Approvals.Notifications() {
			// Already granted this session — the waiter will unblock on its own.
			if engine.Approvals.IsApproved(key) {
				continue
			}
			// Already printing a prompt for this key.
			if handling[key] {
				continue
			}
			handling[key] = true

			// Print immediately — no wait.
			fmt.Println()
			ui.Banner("Approval Required")
			ui.Divider()
			ui.StatusRow("Secret:", ui.BrandStyle.Render(key.SecretKey))
			agent := key.AgentID
			if agent == "" {
				agent = "(anonymous)"
			}
			ui.StatusRow("Agent:", agent)
			ui.StatusRow("Request:", fmt.Sprintf("%s → %s", key.Method, key.Domain))
			fmt.Println()
			fmt.Print(ui.WarningStyle.Render("Allow? [y/N/always]: "))

			var response string
			fmt.Fscanln(os.Stdin, &response)
			response = strings.TrimSpace(strings.ToLower(response))

			switch response {
			case "y", "yes", "always":
				engine.Approvals.Approve(key)
				ui.Success(fmt.Sprintf("Approved: %s for %s → %s (this session)", key.SecretKey, key.Method, key.Domain))
				if response == "always" {
					ui.Info("'always' grants approval for this proxy session only — restart proxy to reset.")
				}
				// Keep in handling — already granted, future requests unblock instantly.
			default:
				engine.Approvals.Deny(key)
				ui.Warning(fmt.Sprintf("Denied: %s for %s → %s", key.SecretKey, key.Method, key.Domain))
				// Remove from handling so a future request for the same key re-prompts.
				delete(handling, key)
			}

			fmt.Println()
		}
	}()
}

var proxyRotateSessionCmd = &cobra.Command{
	Use:   "rotate-session",
	Short: "Rotate the local proxy session token",
	Long:  `Generate a new session token, notify the running proxy daemon, and update the secure local session storage.`,
	RunE:  runProxyRotateSession,
}

func runProxyRotateSession(cmd *cobra.Command, args []string) error {
	fmt.Println()
	ui.Banner("Rotate Session Token")
	ui.Divider()

	// Read current session token
	oldToken, err := proxy.ReadSessionToken()
	if err != nil {
		return fmt.Errorf("failed to read current session token: %w", err)
	}

	// Determine port from PID file or default
	port := 8765
	_, _, pidPort, err := proxy.ReadPIDFile()
	if err == nil && pidPort > 0 {
		port = pidPort
	}

	// Notify running proxy server. The new token is generated server-side and
	// returned; the client never chooses it (trusting a client-supplied token
	// would let anyone who can reach the endpoint pick the session key).
	url := fmt.Sprintf("http://localhost:%d/rotate-session", port)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return fmt.Errorf("failed to build rotation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AS-Session-Token", oldToken)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		ui.Warning("Proxy daemon is not currently running. Cannot rotate without a running daemon.")
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("proxy rejected session rotation: %s", string(respBody))
	}

	var rotResp struct {
		Status   string `json:"status"`
		Message  string `json:"message"`
		NewToken string `json:"new_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rotResp); err != nil {
		return fmt.Errorf("failed to decode rotation response: %w", err)
	}
	if rotResp.NewToken == "" {
		return fmt.Errorf("proxy returned no new session token")
	}

	// Persist the server-generated token to the keyring.
	if err := proxy.WriteSessionToken(rotResp.NewToken); err != nil {
		return fmt.Errorf("failed to store new session token: %w", err)
	}

	ui.Success("Running proxy daemon updated with new session token (server-generated).")
	ui.Success("Session token rotated successfully in secure OS Keychain.")
	fmt.Println()
	return nil
}
