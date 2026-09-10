package commands

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/log"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/spf13/cobra"
)

func displayTokenID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:4] + "..." + id[len(id)-4:]
}

var (
	logService  *log.Service
	logPageSize = 20
)

var logWatchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Live stream new audit log entries",
	RunE: func(cmd *cobra.Command, args []string) error {
		return watchLogs(logService)
	},
}

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "View and filter the credential call audit log",
	Long:  "Every call made through the AgentSecrets proxy is logged here.\nThe log records which agent made the call, which credential was\nreferenced, which API was called, and what happened — but never\nthe credential value.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureDaemonInitialized(); err != nil {
			return err
		}
		if err := app.Auth().EnsureAuth(cmd, args); err != nil {
			return err
		}
		var err error
		logService, err = log.NewService(app.API(), nil)
		if err != nil {
			return fmt.Errorf("could not initialize log service: %v", err)
		}
		return nil
	},
	RunE: runLogList,
}

var logShowCmd = &cobra.Command{
	Use:   "show <log_id>",
	Short: "Show a single entry in full",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		cfg, _ := config.LoadGlobalConfig()
		wsID := config.GetSelectedWorkspaceID()
		var entry *proxy.AuditEvent
		var err error

		if cfg != nil && wsID != "" && strings.EqualFold(cfg.Workspaces[wsID].Type, "shared") {
			entry, err = logService.GetRemoteLog(id)
			if err != nil {
				return errors.New(errors.ErrLogNotFound, fmt.Sprintf("log entry %q not found remotely: %v", id, err), err)
			}
			showLogDetail(*entry)
			return nil
		}

		fe, err := logService.GetForensicLog(id)
		if err == nil {
			showForensicLogDetail(fe)
			return nil
		}

		entry, err = logService.GetLog(id)
		if err != nil {
			return errors.New(errors.ErrLogNotFound, fmt.Sprintf("log entry %q not found locally", id), err)
		}
		showLogDetail(*entry)
		return nil
	},
}

var logSummaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Aggregate statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		since, _ := cmd.Flags().GetString("since")
		filter := buildFilter(cmd, since)

		logs, err := queryLogs(filter)
		if err != nil {
			return err
		}

		total := len(logs)
		if total == 0 {
			fmt.Println("No logs found for the given criteria.")
			return nil
		}

		succeeded := 0
		failed := 0
		redacted := 0
		identities := map[string]int{"issued": 0, "declared": 0, "anonymous": 0}
		agentCounts := make(map[string]int)
		agentFailed := make(map[string]int)
		credCounts := make(map[string]int)
		domainCounts := make(map[string]int)

		for _, l := range logs {
			isFailed := l.StatusCode >= 400 || l.Status == "BLOCKED"
			if isFailed {
				failed++
			} else {
				succeeded++
			}
			if l.Redacted {
				redacted++
			}
			level := l.IdentityLevel
			if level == "" {
				level = "anonymous"
			}
			identities[level]++

			ag := l.AgentID
			if ag == "" {
				ag = "(anonymous)"
			}
			agentCounts[ag]++
			if isFailed {
				agentFailed[ag]++
			}

			for _, key := range l.SecretKeys {
				credCounts[key]++
			}

			if l.Domain != "" {
				domainCounts[l.Domain]++
			}
		}

		fmt.Println("LOG SUMMARY")
		fmt.Println("────────────────────────────────────────────────────")
		fmt.Printf("Total calls       %d\n", total)
		fmt.Printf("  Succeeded       %d  (%.1f%%)\n", succeeded, float64(succeeded)/float64(total)*100)
		fmt.Printf("  Failed          %d  (%.1f%%)\n", failed, float64(failed)/float64(total)*100)
		fmt.Printf("  Redacted        %d\n\n", redacted)

		fmt.Println("By identity level")
		fmt.Printf("  Issued          %d\n", identities["issued"])
		fmt.Printf("  Declared        %d\n", identities["declared"])
		fmt.Printf("  Anonymous       %d\n", identities["anonymous"])

		// By agent breakdown
		fmt.Println("\nBy agent")
		printTopN(agentCounts, agentFailed, 5)

		// By credential breakdown
		fmt.Println("\nBy credential")
		printTopN(credCounts, nil, 5)

		// By domain breakdown
		fmt.Println("\nBy domain")
		printTopN(domainCounts, nil, 5)

		if identities["anonymous"] > 0 {
			fmt.Println("\n" + ui.WarningStyle.Render(fmt.Sprintf("%d anonymous calls detected.", identities["anonymous"])))
			fmt.Println("Run: agentsecrets log --identity anonymous")
			fmt.Println("to identify which tools are missing agent identity.")
		}

		return nil
	},
}

// logExportCmd exports audit logs in JSONL or CSV format.
var logExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export audit log entries",
	Long:  "Export audit log entries to a file in JSONL or CSV format.\nThe --since flag is required to scope the export.",
	RunE: func(cmd *cobra.Command, args []string) error {
		sinceStr, _ := cmd.Flags().GetString("since")
		if sinceStr == "" {
			return fmt.Errorf("--since is required for export (e.g. --since 7d)")
		}

		untilStr, _ := cmd.Flags().GetString("until")
		format, _ := cmd.Flags().GetString("format")
		output, _ := cmd.Flags().GetString("output")
		agent, _ := cmd.Flags().GetString("agent")
		credential, _ := cmd.Flags().GetString("credential")

		filter := log.Filter{
			Agent:      agent,
			Credential: credential,
			Limit:      0, // no limit for export
		}
		if sinceStr != "" {
			filter.Since = parseDuration(sinceStr)
		}
		if untilStr != "" {
			filter.Until = parseDuration(untilStr)
		}

		logs, err := queryLogs(filter)
		if err != nil {
			return err
		}

		if len(logs) == 0 {
			fmt.Println(ui.DimStyle.Render("No log entries match your criteria."))
			return nil
		}

		// Determine output writer
		var writer *os.File
		if output != "" && output != "-" {
			writer, err = os.Create(output)
			if err != nil {
				return fmt.Errorf("failed to create output file: %w", err)
			}
			defer writer.Close()
		} else {
			writer = os.Stdout
		}

		switch format {
		case "csv":
			return exportCSV(writer, logs)
		default:
			return exportJSONL(writer, logs)
		}
	},
}

func exportJSONL(writer *os.File, logs []proxy.AuditEvent) error {
	enc := json.NewEncoder(writer)
	for i, l := range logs {
		if err := enc.Encode(l); err != nil {
			return fmt.Errorf("failed to encode log entry: %w", err)
		}
		if i > 0 && i%100 == 0 {
			fmt.Fprintf(os.Stderr, "\rExported %d / %d entries...", i, len(logs))
		}
	}
	if len(logs) > 100 {
		fmt.Fprintf(os.Stderr, "\rExported %d / %d entries... done.\n", len(logs), len(logs))
	}
	return nil
}

func exportCSV(writer *os.File, logs []proxy.AuditEvent) error {
	w := csv.NewWriter(writer)
	defer w.Flush()

	// Write headers
	headers := []string{"id", "timestamp", "environment", "agent_id", "identity_level", "method", "target_url", "domain", "status_code", "duration_ms", "status", "reason", "redacted", "secret_keys", "auth_styles"}
	if err := w.Write(headers); err != nil {
		return fmt.Errorf("failed to write CSV headers: %w", err)
	}

	for i, l := range logs {
		redacted := "false"
		if l.Redacted {
			redacted = "true"
		}
		row := []string{
			l.ID,
			l.Timestamp.Format(time.RFC3339),
			l.Environment,
			l.AgentID,
			l.IdentityLevel,
			l.Method,
			l.TargetURL,
			l.Domain,
			fmt.Sprintf("%d", l.StatusCode),
			fmt.Sprintf("%d", l.DurationMs),
			l.Status,
			l.Reason,
			redacted,
			strings.Join(l.SecretKeys, ";"),
			strings.Join(l.AuthStyles, ";"),
		}
		if err := w.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
		if i > 0 && i%100 == 0 {
			fmt.Fprintf(os.Stderr, "\rExported %d / %d entries...", i, len(logs))
		}
	}
	if len(logs) > 100 {
		fmt.Fprintf(os.Stderr, "\rExported %d / %d entries... done.\n", len(logs), len(logs))
	}
	return nil
}

// printTopN prints the top N entries from a counts map, with optional failure counts.
// Pass nil for failedCounts when failure breakdown is not needed.
func printTopN(counts map[string]int, failedCounts map[string]int, n int) {
	type entry struct {
		name  string
		count int
	}
	entries := make([]entry, 0, len(counts))
	for name, count := range counts {
		entries = append(entries, entry{name, count})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].count > entries[j].count })

	for i, e := range entries {
		if i >= n {
			break
		}
		if failedCounts != nil {
			if failed := failedCounts[e.name]; failed > 0 {
				fmt.Printf("  %-18s %d  (%d failed)\n", e.name, e.count, failed)
				continue
			}
		}
		fmt.Printf("  %-18s %d\n", e.name, e.count)
	}
}

func parseDuration(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if strings.HasSuffix(s, "d") {
		days := 0
		fmt.Sscanf(s, "%dd", &days)
		return time.Now().AddDate(0, 0, -days)
	}
	d, err := time.ParseDuration(s)
	if err == nil {
		return time.Now().Add(-d)
	}
	t, err := time.Parse("2006-01-02", s)
	if err == nil {
		return t
	}
	return time.Time{}
}

func buildFilter(cmd *cobra.Command, sinceStr string) log.Filter {
	f := log.Filter{}
	f.Agent, _ = cmd.Flags().GetString("agent")
	f.Token, _ = cmd.Flags().GetString("token")
	f.Identity, _ = cmd.Flags().GetString("identity")
	f.Credential, _ = cmd.Flags().GetString("credential")
	f.Domain, _ = cmd.Flags().GetString("domain")
	f.Method, _ = cmd.Flags().GetString("method")
	f.Status, _ = cmd.Flags().GetInt("status")
	f.StatusClass, _ = cmd.Flags().GetString("status-class")
	f.Failed, _ = cmd.Flags().GetBool("failed")
	f.Blocked, _ = cmd.Flags().GetBool("blocked")
	f.Redacted, _ = cmd.Flags().GetBool("redacted")
	f.ProjectID, _ = cmd.Flags().GetString("project")
	f.Environment, _ = cmd.Flags().GetString("env")
	f.Limit, _ = cmd.Flags().GetInt("limit")
	f.ExcludeManagement = true

	untilStr, _ := cmd.Flags().GetString("until")
	if sinceStr != "" {
		f.Since = parseDuration(sinceStr)
	}
	if untilStr != "" {
		f.Until = parseDuration(untilStr)
	}

	return f
}

// colorStatus returns a color-coded status string based on the HTTP status code.
func colorStatus(statusCode int, status string) string {
	if status == "BLOCKED" {
		return ui.ErrorStyle.Render("BLOCKED")
	}
	s := fmt.Sprintf("%d", statusCode)
	switch {
	case statusCode >= 200 && statusCode < 300:
		return ui.SuccessStyle.Render(s)
	case statusCode >= 300 && statusCode < 500:
		return ui.WarningStyle.Render(s)
	case statusCode >= 500:
		return ui.ErrorStyle.Render(s)
	default:
		return s
	}
}

func queryLogs(filter log.Filter) ([]proxy.AuditEvent, error) {
	cfg, err := config.LoadGlobalConfig()
	if err != nil {
		return nil, err
	}
	wsID := config.GetSelectedWorkspaceID()
	if wsID == "" {
		return nil, fmt.Errorf("no workspace selected")
	}
	filter.WorkspaceID = wsID

	// Resolve project name/slug to project UUID if provided
	if filter.ProjectID != "" {
		projSvc := app.Projects()
		if list, err := projSvc.List(); err == nil {
			for _, p := range list {
				if strings.EqualFold(p.ID, filter.ProjectID) || strings.EqualFold(p.Name, filter.ProjectID) {
					filter.ProjectID = p.ID
					break
				}
			}
		}
	}

	ws := cfg.Workspaces[wsID]
	if strings.EqualFold(ws.Type, "shared") {
		return logService.QueryRemote(wsID, filter)
	}
	return logService.QueryLocal(filter)
}

func runLogListWithFilter(cmd *cobra.Command, filter log.Filter) error {
	useJSON, _ := cmd.Flags().GetBool("json")
	useTail, _ := cmd.Flags().GetBool("tail")

	if useTail {
		return watchLogs(logService)
	}

	if useJSON {
		logs, err := queryLogs(filter)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		for _, l := range logs {
			enc.Encode(l)
		}
		return nil
	}

	offset := 0
	for {
		filter.Limit = logPageSize
		filter.Offset = offset
		logs, err := queryLogs(filter)
		if err != nil {
			return err
		}

		if len(logs) == 0 && offset == 0 {
			fmt.Println(ui.DimStyle.Render("No log entries match your criteria."))
			return nil
		}

		fmt.Print("\033[H\033[2J")
		ui.Banner("Audit Log")
		fmt.Printf("Showing page %d (entries %d-%d)\n\n", (offset/logPageSize)+1, offset+1, offset+len(logs))

		headers := []string{"#", "TIME", "ENV", "AGENT", "IDENTITY", "CREDENTIAL", "DOMAIN", "STATUS", "DUR"}
		rows := [][]string{}

		anonymousCount := 0
		for i, l := range logs {
			idx := fmt.Sprintf("%d", i+1)
			t := l.Timestamp.Format("15:04:05")
			ag := l.AgentID
			if ag == "" {
				ag = "(anon)"
			}
			ident := l.IdentityLevel
			if ident == "" {
				ident = "anonymous"
			}

			if ident == "anonymous" {
				anonymousCount++
			}

			cred := "(none)"
			if len(l.SecretKeys) > 0 {
				cred = l.SecretKeys[0]
				if len(l.SecretKeys) > 1 {
					cred = fmt.Sprintf("%s +%d", cred, len(l.SecretKeys)-1)
				}
			}

			domain := l.Domain
			status := colorStatus(l.StatusCode, l.Status)
			dur := fmt.Sprintf("%dms", l.DurationMs)

			rows = append(rows, []string{idx, t, l.Environment, ag, ident, cred, domain, status, dur})
		}

		fmt.Println(ui.RenderTable(headers, rows))

		// Anonymous call hint
		if anonymousCount > 0 {
			fmt.Println("\n" + ui.WarningStyle.Render(fmt.Sprintf("%d anonymous calls detected.", anonymousCount)))
			fmt.Println("Run: agentsecrets logs --identity anonymous")
		}

		fmt.Println("\n" + ui.DimStyle.Render("Navigation: [n]ext, [p]rev, [1-20] for detail, [q]uit"))
		fmt.Print("Action: ")

		var input string
		fmt.Scanln(&input)
		input = strings.ToLower(strings.TrimSpace(input))

		switch input {
		case "n":
			if len(logs) == logPageSize {
				offset += logPageSize
			}
		case "p":
			if offset >= logPageSize {
				offset -= logPageSize
			}
		case "q":
			return nil
		default:
			idx := 0
			if _, err := fmt.Sscanf(input, "%d", &idx); err == nil {
				if idx > 0 && idx <= len(logs) {
					fe, err := logService.GetForensicLog(logs[idx-1].ID)
					if err == nil {
						showForensicLogDetail(fe)
					} else {
						showLogDetail(logs[idx-1])
					}
					fmt.Println("\nPress Enter to return to list...")
					fmt.Scanln()
				}
			}
		}
	}
}

func runLogList(cmd *cobra.Command, args []string) error {
	sinceStr, _ := cmd.Flags().GetString("since")
	filter := buildFilter(cmd, sinceStr)
	return runLogListWithFilter(cmd, filter)
}

func runProjectLogs(cmd *cobra.Command, args []string) error {
	sinceStr, _ := cmd.Flags().GetString("since")
	filter := buildFilter(cmd, sinceStr)

	var projectID string
	if pc, err := config.LoadProjectConfig(); err == nil && pc != nil {
		projectID = pc.ProjectID
	} else {
		cfg, _ := config.LoadGlobalConfig()
		if cfg != nil {
			projectID = cfg.SelectedProjectID
		}
	}
	if projectID == "" {
		return fmt.Errorf("no project selected — run 'agentsecrets project use' first")
	}
	filter.ProjectID = projectID

	return runLogListWithFilter(cmd, filter)
}

// displayLogBasic prints a single log entry in the spec format:
// 14:22:01  billing-tool  →  api.stripe.com  POST /v1/charges  200  143ms
func displayLogBasic(l proxy.AuditEvent) {
	t := l.Timestamp.Format("15:04:05")
	ag := l.AgentID
	if ag == "" {
		ag = "(anon)"
	}

	// Extract path from target URL
	path := ""
	if u, err := url.Parse(l.TargetURL); err == nil {
		path = u.Path
	}

	status := colorStatus(l.StatusCode, l.Status)
	dur := fmt.Sprintf("%dms", l.DurationMs)
	env := l.Environment
	if env == "" {
		env = "dev"
	} // fallback for display

	fmt.Printf("%s  [%s]  %s  →  %s  %s %s  %s  %s\n", t, env, ag, l.Domain, strings.ToUpper(l.Method), path, status, dur)
}

func showLogDetail(entry proxy.AuditEvent) {
	fmt.Println("\n─────────────────────────────────────────────────────────")
	fmt.Printf("LOG ENTRY  %s\n", entry.ID)
	fmt.Println("─────────────────────────────────────────────────────────")
	ui.StatusRow("Timestamp", entry.Timestamp.Format("2006-01-02 15:04:05.000 MST"))

	ui.StatusRow("Workspace", entry.WorkspaceID)
	ui.StatusRow("Project", entry.ProjectID)
	ui.StatusRow("Environment", entry.Environment)

	ui.StatusRow("Agent", entry.AgentID)
	ui.StatusRow("Token", entry.TokenID)
	ui.StatusRow("Identity Level", entry.IdentityLevel)

	ui.StatusRow("Credentials", strings.Join(entry.SecretKeys, ", "))
	ui.StatusRow("Injection", strings.Join(entry.AuthStyles, ", "))

	ui.StatusRow("Target", fmt.Sprintf("%s %s", strings.ToUpper(entry.Method), entry.TargetURL))
	ui.StatusRow("Domain", entry.Domain)

	statusText := fmt.Sprintf("%d", entry.StatusCode)
	if entry.Status == "BLOCKED" {
		statusText = "BLOCKED (" + entry.Reason + ")"
	}

	ui.StatusRow("Status", statusText)
	ui.StatusRow("Duration", fmt.Sprintf("%dms", entry.DurationMs))
	ui.StatusRow("Resolution", entry.ResolutionPath)
	ui.StatusRow("Caller Role", entry.CallerRole)
	fmt.Println("─────────────────────────────────────────────────────────")
}

func showForensicLogDetail(fe *proxy.ForensicAuditEvent) {
	fmt.Println("─────────────────────────────────────────────────────────")
	fmt.Printf("FORENSIC LOG ENTRY  %s\n", fe.ID)
	fmt.Println("─────────────────────────────────────────────────────────")
	ui.StatusRow("Timestamp", fe.CreatedAt.Format("2006-01-02 15:04:05.000 MST"))
	ui.StatusRow("Schema Version", fe.Version)
	ui.StatusRow("Workspace ID", fe.WorkspaceID)
	ui.StatusRow("Project ID", fe.ProjectID)
	ui.StatusRow("Chain Hash", fe.ChainHash)
	fmt.Println()

	fmt.Println(ui.BrandStyle.Render("● EVENT DETAILS"))
	ui.StatusRow("  Type", fe.Event.Type)
	ui.StatusRow("  Environment", fe.Event.Environment)
	ui.StatusRow("  Key Name", fe.Event.KeyName)
	ui.StatusRow("  Target", fmt.Sprintf("%s https://%s%s", strings.ToUpper(fe.Event.Method), fe.Event.Domain, fe.Event.Path))
	ui.StatusRow("  Domain", fe.Event.Domain)
	ui.StatusRow("  Path", fe.Event.Path)
	ui.StatusRow("  Status Code", fmt.Sprintf("%d", fe.Event.StatusCode))
	ui.StatusRow("  Outcome", fe.Event.Outcome)
	ui.StatusRow("  Latency", fmt.Sprintf("%dms", fe.Event.LatencyMs))
	if fe.Event.AgentIdentity != nil {
		ui.StatusRow("  Agent ID", fe.Event.AgentIdentity.TokenName)
		ui.StatusRow("  Agent Token ID", fe.Event.AgentIdentity.TokenID)
		ui.StatusRow("  Identity Level", fe.Event.AgentIdentity.IdentityLevel)
		procVer := "no"
		if fe.Event.AgentIdentity.ProcessVerified {
			procVer = "yes"
		}
		ui.StatusRow("  Process Verified", procVer)
	}
	fmt.Println()

	fmt.Println(ui.BrandStyle.Render("● ENFORCEMENT LAYER"))
	ui.StatusRow("  Decision", fe.Enforcement.Decision)
	ui.StatusRow("  Decided By", fe.Enforcement.DecidedBy)
	if fe.Enforcement.FirstFailureLayer != "" {
		ui.StatusRow("  First Failure", ui.ErrorStyle.Render(fe.Enforcement.FirstFailureLayer))
	}
	fmt.Println("  Layers Evaluated:")
	for _, l := range fe.Enforcement.LayersEvaluated {
		resStr := ui.SuccessStyle.Render("pass")
		if l.Result == "fail" {
			resStr = ui.ErrorStyle.Render("fail")
		}
		fmt.Printf("    - %-20s [%s]  %s\n", l.Layer, resStr, l.Reason)
		if l.ActionRequired != "" {
			fmt.Printf("      %s %s\n", ui.WarningStyle.Render("Action Required:"), l.ActionRequired)
		}
	}
	fmt.Println()

	fmt.Println(ui.BrandStyle.Render("● RESOLUTION LAYER"))
	injectedStr := "no"
	if fe.Resolution.CredentialInjected {
		injectedStr = "yes"
	}
	ui.StatusRow("  Cred Injected", injectedStr)
	if fe.Resolution.InjectionStyle != "" {
		ui.StatusRow("  Injection Style", fe.Resolution.InjectionStyle)
	}
	scannedStr := "no"
	if fe.Resolution.ResponseScanned {
		scannedStr = "yes"
	}
	ui.StatusRow("  Resp Scanned", scannedStr)
	redactedStr := "no"
	if fe.Resolution.RedactionTriggered {
		redactedStr = "yes"
	}
	ui.StatusRow("  Redaction Triggered", redactedStr)
	if fe.Resolution.RedactionPattern != "" {
		ui.StatusRow("  Redact Pattern", fe.Resolution.RedactionPattern)
	}
	if fe.Resolution.RedactedField != "" {
		ui.StatusRow("  Redacted Field", fe.Resolution.RedactedField)
	}
	ssrfStr := "no"
	if fe.Resolution.SSRFCheckPassed {
		ssrfStr = "yes"
	}
	ui.StatusRow("  SSRF Check Passed", ssrfStr)
	ui.StatusRow("  Response Status", fmt.Sprintf("%d", fe.Resolution.ResponseStatus))
	fmt.Println()

	fmt.Println(ui.BrandStyle.Render("● SNAPSHOT STATE AT EVENT TIME"))
	ui.StatusRow("  Captured At", fe.Snapshot.CapturedAt.Format("2006-01-02 15:04:05.000 MST"))
	ui.StatusRow("  Workspace ID", fe.Snapshot.Workspace.ID)
	ui.StatusRow("  Workspace Name", fe.Snapshot.Workspace.Name)
	ui.StatusRow("  Workspace Allowlist", strings.Join(fe.Snapshot.Workspace.Allowlist, ", "))
	ui.StatusRow("  Project ID", fe.Snapshot.Project.ID)
	ui.StatusRow("  Project Name", fe.Snapshot.Project.Name)
	ui.StatusRow("  Project Env", fe.Snapshot.Project.Environment)
	ui.StatusRow("  Secrets Count", fmt.Sprintf("%d", fe.Snapshot.SecretsCount))
	ui.StatusRow("  Secrets In Scope", strings.Join(fe.Snapshot.SecretsInScope, ", "))

	if fe.Snapshot.AgentCapabilities != nil {
		fmt.Println("  Agent Capabilities:")
		ui.StatusRow("    Token Name", fe.Snapshot.AgentCapabilities.TokenName)
		ui.StatusRow("    Allowed Projects", strings.Join(fe.Snapshot.AgentCapabilities.AllowedProjects, ", "))
		ui.StatusRow("    Allowed Secrets", strings.Join(fe.Snapshot.AgentCapabilities.AllowedSecrets, ", "))
		ui.StatusRow("    Scopes", strings.Join(fe.Snapshot.AgentCapabilities.Scopes, ", "))
	}
	if fe.Snapshot.SecretsPolicy != nil {
		fmt.Println("  Secrets Policy:")
		ui.StatusRow("    Key Name", fe.Snapshot.SecretsPolicy.KeyName)
		ui.StatusRow("    Allowed Domains", strings.Join(fe.Snapshot.SecretsPolicy.AllowedDomains, ", "))
		ui.StatusRow("    Allowed Methods", strings.Join(fe.Snapshot.SecretsPolicy.AllowedMethods, ", "))
		ui.StatusRow("    Violation Action", fe.Snapshot.SecretsPolicy.ViolationAction)
		ui.StatusRow("    Policy Version", fe.Snapshot.SecretsPolicy.PolicyVersion)
	}
	fmt.Println("  Keychain Auth:")
	authK := "no"
	if fe.Snapshot.KeychainAuth.Authenticated {
		authK = "yes"
	}
	ui.StatusRow("    Authenticated", authK)
	procH := "no"
	if fe.Snapshot.KeychainAuth.ProcessHashVerified {
		procH = "yes"
	}
	ui.StatusRow("    Process Hash Verified", procH)
	sessB := "no"
	if fe.Snapshot.KeychainAuth.SessionBound {
		sessB = "yes"
	}
	ui.StatusRow("    Session Bound", sessB)

	fmt.Println("  Proxy Snapshot:")
	ui.StatusRow("    Version", fe.Snapshot.Proxy.Version)
	ui.StatusRow("    Port", fmt.Sprintf("%d", fe.Snapshot.Proxy.Port))
	transP := "no"
	if fe.Snapshot.Proxy.Transient {
		transP = "yes"
	}
	ui.StatusRow("    Transient", transP)
	fmt.Println("─────────────────────────────────────────────────────────")
}

var logVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the cryptographic integrity of the forensic log chain",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Verifying cryptographic chain integrity...")
		err := logService.VerifyChain()
		if err != nil {
			fmt.Printf("%s Chain integrity failure detected!\n", ui.ErrorStyle.Render("FAIL:"))
			fmt.Printf("  Reason: %v\n", err)
			return fmt.Errorf("cryptographic audit log verification failed")
		}

		fmt.Println(ui.SuccessStyle.Render("Chain integrity: OK"))
		return nil
	},
}

var logReplayCmd = &cobra.Command{
	Use:   "replay <log_id>",
	Short: "Replay the proxy enforcement decision state for a single log",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		fe, err := logService.GetForensicLog(id)
		if err != nil {
			return errors.New(errors.ErrLogNotFound, fmt.Sprintf("forensic log entry %q not found locally", id), err)
		}

		fmt.Println("─────────────────────────────────────────────────────────")
		fmt.Printf("REPLAY STATE FOR EVENT %s\n", fe.ID)
		fmt.Println("─────────────────────────────────────────────────────────")
		fmt.Printf("Timestamp:   %s\n", fe.CreatedAt.Format("2006-01-02 15:04:05.000 MST"))
		fmt.Printf("Action:      %s %s\n", strings.ToUpper(fe.Event.Method), "https://"+fe.Event.Domain+fe.Event.Path)
		fmt.Printf("Environment: %s\n", fe.Event.Environment)
		fmt.Println()

		fmt.Println(ui.BrandStyle.Render("[1/3] Evaluated Agent Capabilities"))
		if fe.Snapshot.AgentCapabilities != nil {
			fmt.Printf("  Agent Token:      %s\n", fe.Snapshot.AgentCapabilities.TokenName)
			fmt.Printf("  Allowed Projects: %s\n", strings.Join(fe.Snapshot.AgentCapabilities.AllowedProjects, ", "))
			fmt.Printf("  Allowed Secrets:  %s\n", strings.Join(fe.Snapshot.AgentCapabilities.AllowedSecrets, ", "))
			fmt.Printf("  Active Scopes:    %s\n", strings.Join(fe.Snapshot.AgentCapabilities.Scopes, ", "))
		} else {
			fmt.Println("  Agent Token:      None (Anonymous mode)")
		}

		capsResult := "PASS"
		capsReason := "Agent has unrestricted access"
		for _, layer := range fe.Enforcement.LayersEvaluated {
			if layer.Layer == "agent_capabilities" {
				if layer.Result == "fail" {
					capsResult = "FAIL"
				}
				capsReason = layer.Reason
			}
		}
		if capsResult == "PASS" {
			fmt.Printf("  Result:           %s (%s)\n", ui.SuccessStyle.Render("PASS"), capsReason)
		} else {
			fmt.Printf("  Result:           %s (%s)\n", ui.ErrorStyle.Render("FAIL"), capsReason)
		}
		fmt.Println()

		fmt.Println(ui.BrandStyle.Render("[2/3] Evaluated Workspace Allowlist"))
		fmt.Printf("  Target Domain:    %s\n", fe.Event.Domain)
		fmt.Printf("  Allowlist count:  %d domains allowed\n", fe.Snapshot.Workspace.AllowlistCount)
		if len(fe.Snapshot.Workspace.Allowlist) > 0 {
			fmt.Printf("  Allowlist:        %s\n", strings.Join(fe.Snapshot.Workspace.Allowlist, ", "))
		}

		allowResult := "PASS"
		allowReason := fmt.Sprintf("Domain %s is permitted by allowlist", fe.Event.Domain)
		for _, layer := range fe.Enforcement.LayersEvaluated {
			if layer.Layer == "workspace_allowlist" {
				if layer.Result == "fail" {
					allowResult = "FAIL"
				}
				allowReason = layer.Reason
			}
		}
		if allowResult == "PASS" {
			fmt.Printf("  Result:           %s (%s)\n", ui.SuccessStyle.Render("PASS"), allowReason)
		} else {
			fmt.Printf("  Result:           %s (%s)\n", ui.ErrorStyle.Render("FAIL"), allowReason)
		}
		fmt.Println()

		fmt.Println(ui.BrandStyle.Render("[3/3] Evaluated Secret Policies"))
		fmt.Printf("  Injected Secret:  %s\n", fe.Event.KeyName)
		if fe.Snapshot.SecretsPolicy != nil {
			fmt.Printf("  Active Policy:    Yes (allowed domains: %s, methods: %s, action: %s)\n",
				strings.Join(fe.Snapshot.SecretsPolicy.AllowedDomains, ", "),
				strings.Join(fe.Snapshot.SecretsPolicy.AllowedMethods, ", "),
				fe.Snapshot.SecretsPolicy.ViolationAction,
			)
		} else {
			fmt.Println("  Active Policy:    None (No restrictions on this key)")
		}

		policyResult := "PASS"
		policyReason := "No violations detected"
		for _, layer := range fe.Enforcement.LayersEvaluated {
			if layer.Layer == "secrets_policy" {
				if layer.Result == "fail" {
					policyResult = "FAIL"
				}
				policyReason = layer.Reason
			}
		}
		if policyResult == "PASS" {
			fmt.Printf("  Result:           %s (%s)\n", ui.SuccessStyle.Render("PASS"), policyReason)
		} else {
			fmt.Printf("  Result:           %s (%s)\n", ui.ErrorStyle.Render("FAIL"), policyReason)
		}
		fmt.Println()

		fmt.Println("─────────────────────────────────────────────────────────")
		fmt.Println(ui.BrandStyle.Render("FINAL ENFORCEMENT DECISION SUMMARY"))
		fmt.Println("─────────────────────────────────────────────────────────")
		decisionColor := ui.SuccessStyle.Render(strings.ToUpper(fe.Enforcement.Decision))
		if fe.Enforcement.Decision == "blocked" || fe.Enforcement.Decision == "policy_denied" {
			decisionColor = ui.ErrorStyle.Render(strings.ToUpper(fe.Enforcement.Decision))
		} else if fe.Enforcement.Decision == "policy_escalated" {
			decisionColor = ui.WarningStyle.Render(strings.ToUpper(fe.Enforcement.Decision))
		}
		ui.StatusRow("Final Decision", decisionColor)
		ui.StatusRow("Decided By", fe.Enforcement.DecidedBy)

		injStr := "Not injected"
		if fe.Resolution.CredentialInjected {
			injStr = fmt.Sprintf("Injected successfully via %s", fe.Resolution.InjectionStyle)
		}
		ui.StatusRow("Credential State", injStr)

		redactStr := "No redaction"
		if fe.Resolution.RedactionTriggered {
			redactStr = ui.WarningStyle.Render("Redaction triggered — secret returned in response was masked")
		}
		ui.StatusRow("Response Redact", redactStr)
		fmt.Println("─────────────────────────────────────────────────────────")

		return nil
	},
}

func init() {
	logsCmd.AddCommand(logShowCmd)
	logsCmd.AddCommand(logSummaryCmd)
	logsCmd.AddCommand(logWatchCmd)
	logsCmd.AddCommand(logExportCmd)
	logsCmd.AddCommand(logVerifyCmd)
	logsCmd.AddCommand(logReplayCmd)

	addFilterFlags := func(c *cobra.Command) {
		c.Flags().String("agent", "", "filter by agent name")
		c.Flags().String("token", "", "filter by specific token ID")
		c.Flags().String("identity", "", "filter by identity level: anonymous, declared, issued")
		c.Flags().String("credential", "", "filter by key name, e.g. STRIPE_KEY")
		c.Flags().String("domain", "", "filter by target domain")
		c.Flags().String("method", "", "filter by HTTP method")
		c.Flags().Int("status", 0, "filter by exact status code")
		c.Flags().String("status-class", "", "filter by class: 2xx, 4xx, 5xx, error")
		c.Flags().Bool("failed", false, "only show calls that failed")
		c.Flags().Bool("blocked", false, "only show calls blocked by the proxy")
		c.Flags().Bool("redacted", false, "only show calls where response was redacted")
		c.Flags().String("project", "", "filter to a specific project")
		c.Flags().String("env", "", "filter by environment (development, staging, production)")
		c.Flags().String("since", "", "e.g. 1h, 24h, 7d")
		c.Flags().String("until", "", "upper bound for time range")
		c.Flags().Int("limit", 50, "number of entries to show (default 50)")
	}

	addFilterFlags(logsCmd)
	logsCmd.Flags().Bool("verbose", false, "full record including allowlist snapshot")
	logsCmd.Flags().Bool("json", false, "output as newline-delimited JSON")
	logsCmd.Flags().Bool("csv", false, "output as CSV with headers")
	logsCmd.Flags().Bool("no-color", false, "disable color output")
	logsCmd.Flags().Bool("tail", false, "live stream new entries (same as log watch)")

	logSummaryCmd.Flags().String("since", "7d", "default: 7d")
	logSummaryCmd.Flags().String("until", "", "")
	logSummaryCmd.Flags().String("agent", "", "")
	logSummaryCmd.Flags().String("project", "", "")
	logSummaryCmd.Flags().String("env", "", "filter by environment")
	logSummaryCmd.Flags().Bool("json", false, "")

	// Export command flags
	logExportCmd.Flags().String("since", "", "start of time range (required, e.g. 7d, 24h, 2024-01-01)")
	logExportCmd.Flags().String("until", "", "end of time range")
	logExportCmd.Flags().String("format", "jsonl", "output format: jsonl or csv")
	logExportCmd.Flags().String("output", "", "output file path (default: stdout)")
	logExportCmd.Flags().String("agent", "", "filter by agent name")
	logExportCmd.Flags().String("credential", "", "filter by key name")
}

// watchLogs polls the local audit database for new entries and prints them as
// they appear. It runs until the process is interrupted with Ctrl+C.
func watchLogs(svc *log.Service) error {
	fmt.Println(ui.BrandStyle.Render("\nWatching audit log... (Ctrl+C to stop)"))
	fmt.Println(ui.DimStyle.Render("Press Enter to refresh manually if needed.\n"))

	lastSeen := time.Now()
	seenIDs := make(map[string]bool)

	for {
		filter := log.Filter{
			Since: lastSeen,
			Limit: 20,
		}
		logs, err := queryLogs(filter)
		if err == nil && len(logs) > 0 {
			// Logs come in newest first
			for i := len(logs) - 1; i >= 0; i-- {
				l := logs[i]
				if seenIDs[l.ID] {
					continue
				}

				displayLogBasic(l)
				seenIDs[l.ID] = true

				if l.Timestamp.After(lastSeen) {
					lastSeen = l.Timestamp
					// Clear seenIDs when timestamp advances to keep map small,
					// but keep IDs for the current lastSeen timestamp.
					for id := range seenIDs {
						delete(seenIDs, id)
					}
					seenIDs[l.ID] = true
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
}
