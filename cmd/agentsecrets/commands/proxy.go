package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var (
	proxyPort      int
	logsSecretFlag string
	logsLastFlag   int
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

var proxyLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "View proxy audit log",
	Long:  `View the audit log of API calls made through the proxy. Shows secret key names, target URLs, and response codes. Never shows secret values.`,
	RunE:  runProxyLogs,
}

func init() {
	proxyStartCmd.Flags().IntVar(&proxyPort, "port", 8765, "Port to listen on")

	proxyLogsCmd.Flags().StringVar(&logsSecretFlag, "secret", "", "Filter logs by secret key name")
	proxyLogsCmd.Flags().IntVar(&logsLastFlag, "last", 20, "Number of recent log entries to show")

	proxyCmd.AddCommand(proxyStartCmd)
	proxyCmd.AddCommand(proxyStatusCmd)
	proxyCmd.AddCommand(proxyLogsCmd)
}

func runProxyStart(cmd *cobra.Command, args []string) error {
	fmt.Println()
	ui.Banner("AgentSecrets Proxy")
	ui.Divider()

	// Load project context
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		ui.Error("No project found. Run 'agentsecrets project use <name>' first.")
		return nil
	}

	ui.StatusRow("Project:", project.ProjectName)
	ui.StatusRow("Port:", fmt.Sprintf("%d", proxyPort))
	fmt.Println()

	engine, err := proxy.NewEngine(project.ProjectID)
	if err != nil {
		ui.Error(fmt.Sprintf("Failed to initialize proxy engine: %v", err))
		return nil
	}

	server := proxy.NewServer(proxyPort, engine)

	ui.Success(fmt.Sprintf("Proxy listening on http://localhost:%d/proxy", proxyPort))
	ui.Info("Press Ctrl+C to stop")
	fmt.Println()

	return server.Start()
}

func runProxyStatus(cmd *cobra.Command, args []string) error {
	fmt.Println()
	ui.Banner("Proxy Status")
	ui.Divider()

	// Simple check: try to read the log file to see if there's activity
	logPath, err := proxy.DefaultLogPath()
	if err != nil {
		ui.StatusRowDim("Log file:", "Not found")
	} else {
		info, err := os.Stat(logPath)
		if err != nil {
			ui.StatusRowDim("Log file:", "No audit log yet")
		} else {
			ui.StatusRow("Log file:", logPath)
			ui.StatusRow("Log size:", fmt.Sprintf("%d bytes", info.Size()))
			ui.StatusRow("Last modified:", info.ModTime().Format(time.RFC3339))
		}
	}

	fmt.Println()
	ui.Info("To start the proxy: agentsecrets proxy start")
	fmt.Println()
	return nil
}

func runProxyLogs(cmd *cobra.Command, args []string) error {
	fmt.Println()
	ui.Banner("Proxy Audit Log")

	logPath, err := proxy.DefaultLogPath()
	if err != nil {
		ui.Error("Could not determine log file path")
		return nil
	}

	f, err := os.Open(logPath)
	if err != nil {
		ui.Info("No audit log found. The proxy hasn't been used yet.")
		fmt.Println()
		return nil
	}
	defer f.Close()

	// Read all lines
	var events []proxy.AuditEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event proxy.AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue // skip malformed lines
		}

		// Apply secret filter
		if logsSecretFlag != "" {
			found := false
			for _, k := range event.SecretKeys {
				if k == logsSecretFlag {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		events = append(events, event)
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

	// Take last N
	start := 0
	if logsLastFlag > 0 && logsLastFlag < len(events) {
		start = len(events) - logsLastFlag
	}
	events = events[start:]

	// Display as table
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
			statusStr = ui.ErrorStyle.Render("✗ BLOCK")
		} else if statusStr == "OK" {
			statusStr = ui.SuccessStyle.Render("✓ OK")
		} else {
			statusStr = "✓ OK" // backward compat for old logs
		}

		reasonStr := e.Reason
		if reasonStr == "" {
			reasonStr = "-"
		statusStr := fmt.Sprintf("%d", e.StatusCode)
		if e.Redacted {
			statusStr += " " + ui.ErrorStyle.Render("(REDACTED)")
		}

		rows[len(events)-1-i] = []string{
			e.Timestamp.Format("15:04:05"),
			statusStr,
			e.Method,
			targetURL,
			strings.Join(e.SecretKeys, ", "),
			strings.Join(e.AuthStyles, ", "),
			fmt.Sprintf("%d", e.StatusCode),
			reasonStr,
			statusStr,
			fmt.Sprintf("%dms", e.DurationMs),
		}
	}

	table := ui.RenderTable(headers, rows)
	fmt.Printf("%s\n", table)

	ui.Info(fmt.Sprintf("Showing %d of %d entries", len(events), len(events)+start))
	fmt.Println()
	return nil
}
