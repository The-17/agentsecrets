package mcp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/The-17/agentsecrets/pkg/agents"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keychainauth"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/log"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/secrets"
	"github.com/mark3labs/mcp-go/mcp"
)

// SafeProxyLog represents a sanitized audit log event safe for AI consumption.
type SafeProxyLog struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	Environment   string    `json:"environment"`
	SecretKeys    []string  `json:"secret_keys"`
	AgentID       string    `json:"agent_id,omitempty"`
	IdentityLevel string    `json:"identity_level"`
	Method        string    `json:"method"`
	TargetURL     string    `json:"target_url"`
	Domain        string    `json:"domain"`
	StatusCode    int       `json:"status_code"`
	DurationMs    int64     `json:"duration_ms"`
	Status        string    `json:"status"`
	Reason        string    `json:"reason,omitempty"`
	Redacted      bool      `json:"redacted"`
}

func toSafeProxyLogs(events []proxy.AuditEvent) []SafeProxyLog {
	res := make([]SafeProxyLog, len(events))
	for i, ev := range events {
		res[i] = SafeProxyLog{
			ID:            ev.ID,
			Timestamp:     ev.Timestamp,
			Environment:   ev.Environment,
			SecretKeys:    ev.SecretKeys,
			AgentID:       ev.AgentID,
			IdentityLevel: ev.IdentityLevel,
			Method:        ev.Method,
			TargetURL:     ev.TargetURL,
			Domain:        ev.Domain,
			StatusCode:    ev.StatusCode,
			DurationMs:    ev.DurationMs,
			Status:        ev.Status,
			Reason:        ev.Reason,
			Redacted:      ev.Redacted,
		}
	}
	return res
}

// --- Tool Definitions ---

func listKeysTool() mcp.Tool {
	return mcp.NewTool("list_keys",
		mcp.WithDescription(
			"List available secret key names in the current project and environment. "+
				"Returns ONLY key names and metadata, never actual values. "+
				"Shows which environment is active and key count per environment. "+
				"By default reads from the local keyring cache (fast). Pass remote=true to fetch latest from the cloud API.",
		),
		mcp.WithBoolean("remote",
			mcp.Description("If true, fetch key list from the cloud API instead of the local keyring cache. Default: false."),
		),
	)
}

func checkKeyTool() mcp.Tool {
	return mcp.NewTool("check_key",
		mcp.WithDescription(
			"Check if a specific secret key exists in the current project. "+
				"Returns existence status, which environments contain the key, and last update time. "+
				"Never returns the actual secret value.",
		),
		mcp.WithString("key_name",
			mcp.Required(),
			mcp.Description("The name of the secret key to check (e.g. STRIPE_KEY)"),
		),
		mcp.WithString("environment",
			mcp.Description("Optional environment to check (development, staging, or production). Defaults to checking all."),
		),
	)
}

func getCoverageTool() mcp.Tool {
	return mcp.NewTool("get_coverage",
		mcp.WithDescription(
			"Show secret key coverage across every environment (development, staging, production, and any custom ones). "+
				"Identifies keys missing from specific environments to help ensure parity.",
		),
	)
}

func getStatusTool() mcp.Tool {
	return mcp.NewTool("get_status",
		mcp.WithDescription(
			"Get the current AgentSecrets status including authentication state, active project, environment, proxy status, and keychain-auth health.",
		),
	)
}

func getEnvironmentTool() mcp.Tool {
	return mcp.NewTool("get_environment",
		mcp.WithDescription(
			"Get the active environment (development/staging/production) and how it was resolved (env var, project config, or global default).",
		),
	)
}

func diffSecretsTool() mcp.Tool {
	return mcp.NewTool("diff_secrets",
		mcp.WithDescription(
			"Compare local secrets (.env/keychain) against cloud secrets for the current environment. "+
				"Shows which keys are added locally, removed from cloud, changed, or unchanged. "+
				"Never shows actual secret values.",
		),
		mcp.WithString("environment",
			mcp.Description("Optional environment to diff (development, staging, production, or a custom name). Defaults to active env."),
		),
	)
}

func diffEnvironmentsTool() mcp.Tool {
	return mcp.NewTool("diff_environments",
		mcp.WithDescription(
			"Compare secret keys between two environments to identify drift. "+
				"Shows which keys exist in one environment but not the other. "+
				"Never shows actual values.",
		),
		mcp.WithString("source",
			mcp.Required(),
			mcp.Description("The source environment (e.g. development)"),
		),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("The target environment (e.g. production)"),
		),
	)
}

func getProxyLogsTool() mcp.Tool {
	return mcp.NewTool("get_proxy_logs",
		mcp.WithDescription(
			"Query local proxy audit logs. Returns recent API calls made through the proxy with metadata (method, domain, status, key names used). "+
				"Never includes response bodies or secret values.",
		),
		mcp.WithString("key_name",
			mcp.Description("Optional: Filter by secret key name used (e.g. STRIPE_KEY)"),
		),
		mcp.WithString("domain",
			mcp.Description("Optional: Filter by target API domain name (e.g. api.stripe.com)"),
		),
		mcp.WithString("limit",
			mcp.Description("Optional: Maximum number of logs to return. Default: 20"),
		),
		mcp.WithString("since",
			mcp.Description("Optional: RFC3339 timestamp filter (e.g. 2026-05-27T18:00:00Z)"),
		),
	)
}

func getBlockedRequestsTool() mcp.Tool {
	return mcp.NewTool("get_blocked_requests",
		mcp.WithDescription(
			"List API requests that were blocked by the proxy (e.g. domain not in allowlist). Helps diagnose why API calls are failing.",
		),
		mcp.WithString("limit",
			mcp.Description("Optional: Maximum number of logs to return. Default: 20"),
		),
	)
}

func getRedactionEventsTool() mcp.Tool {
	return mcp.NewTool("get_redaction_events",
		mcp.WithDescription(
			"List requests where the proxy detected and redacted secret values from responses. Helps identify potential credential leakage in API responses.",
		),
		mcp.WithString("limit",
			mcp.Description("Optional: Maximum number of logs to return. Default: 20"),
		),
	)
}

func getAuditSummaryTool() mcp.Tool {
	return mcp.NewTool("get_audit_summary",
		mcp.WithDescription(
			"Get an aggregate summary of proxy audit activity: total calls, unique domains, unique credentials used, blocked/redacted counts, and breakdown by environment.",
		),
	)
}

func getAgentIdentityTool() mcp.Tool {
	return mcp.NewTool("get_agent_identity",
		mcp.WithDescription(
			"Get the current agent's identity information including authentication status, keychain-auth configuration, and whether an agent token (AS_AGENT_TOKEN) is set.",
		),
	)
}

func listAgentTokensTool() mcp.Tool {
	return mcp.NewTool("list_agent_tokens",
		mcp.WithDescription(
			"List all registered agent identities and their tokens for the current workspace. Shows token metadata (label, status, created/expiry dates) but never the token values.",
		),
	)
}

func checkDomainTool() mcp.Tool {
	return mcp.NewTool("check_domain",
		mcp.WithDescription(
			"Check if a domain is in the workspace proxy allowlist. If the domain is not allowed, returns the CLI command the user should run to add it.",
		),
		mcp.WithString("domain",
			mcp.Required(),
			mcp.Description("The domain name to check (e.g. api.stripe.com)"),
		),
	)
}

func getAllowlistTool() mcp.Tool {
	return mcp.NewTool("get_allowlist",
		mcp.WithDescription(
			"Get the full proxy allowlist for the current workspace. Only domains in this list can receive injected credentials.",
		),
	)
}

// --- Handlers ---

func (s *Server) handleListKeys(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	remoteFlag, _ := args["remote"].(bool)

	activeEnv := config.ResolveEnvironment()

	projectID, _ := config.ResolveProjectContext()
	if projectID == "" {
		return mcp.NewToolResultError("no project configured in current directory"), nil
	}

	root, _ := config.GetProjectRoot()
	envs, err := s.getSecretsService().Environments(projectID, root)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	presence := make(map[string][]bool)
	allKeysSet := make(map[string]bool)
	keyCount := make(map[string]int)

	var svc *secrets.Service
	if remoteFlag {
		svc = s.getSecretsService()
	}

	for i, env := range envs {
		var keyNames []string
		if remoteFlag {
			list, err := svc.ListForEnv(env)
			if err == nil {
				for _, item := range list {
					keyNames = append(keyNames, item.Key)
				}
			}
		} else {
			keyNames, _ = keyring.ListProjectKeyNames(projectID, env)
		}
		keyCount[env] = len(keyNames)
		for _, k := range keyNames {
			p := presence[k]
			if p == nil {
				p = make([]bool, len(envs))
			}
			p[i] = true
			presence[k] = p
			allKeysSet[k] = true
		}
	}

	keys := make([]string, 0, len(allKeysSet))
	for k := range allKeysSet {
		keys = append(keys, k)
	}

	source := "local_keyring"
	if remoteFlag {
		source = "api"
	}

	result := map[string]interface{}{
		"active_environment": activeEnv,
		"keys":               keys,
		"key_count":          keyCount,
		"total_unique_keys":  len(allKeysSet),
		"source":             source,
	}
	if !remoteFlag {
		result["hint"] = "Showing cached keys. Pass remote=true for latest from cloud."
	}

	return jsonResult(result)
}

func (s *Server) handleCheckKey(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	keyName, _ := args["key_name"].(string)
	if keyName == "" {
		return mcp.NewToolResultError("missing required parameter: key_name"), nil
	}

	envParam, _ := args["environment"].(string)
	svc := s.getSecretsService()

	type envStatus struct {
		Exists    bool   `json:"exists"`
		UpdatedAt string `json:"updated_at,omitempty"`
	}

	resEnvs := make(map[string]envStatus)
	existsAnywhere := false

	envsToCheck := config.StandardEnvironments
	if projectID, _ := config.ResolveProjectContext(); projectID != "" {
		root, _ := config.GetProjectRoot()
		if all, err := s.getSecretsService().Environments(projectID, root); err == nil {
			envsToCheck = all
		}
	}
	if envParam != "" {
		env, err := config.ParseEnvironment(envParam)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		envsToCheck = []string{env}
	}

	for _, env := range envsToCheck {
		list, err := svc.ListForEnv(env)
		if err != nil {
			resEnvs[env] = envStatus{Exists: false}
			continue
		}
		found := false
		var updatedAt string
		for _, item := range list {
			if strings.EqualFold(item.Key, keyName) {
				found = true
				updatedAt = item.UpdatedAt
				existsAnywhere = true
				break
			}
		}
		resEnvs[env] = envStatus{Exists: found, UpdatedAt: updatedAt}
	}

	return jsonResult(map[string]interface{}{
		"key_name":     keyName,
		"exists":       existsAnywhere,
		"environments": resEnvs,
	})
}

func (s *Server) handleGetCoverage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc := s.getSecretsService()

	envs := config.StandardEnvironments
	if projectID, _ := config.ResolveProjectContext(); projectID != "" {
		root, _ := config.GetProjectRoot()
		if all, err := svc.Environments(projectID, root); err == nil {
			envs = all
		}
	}

	lists := make(map[string][]secrets.SecretMetadata)
	allUniqueKeys := make(map[string]bool)

	for _, env := range envs {
		list, err := svc.ListForEnv(env)
		if err == nil {
			lists[env] = list
			for _, item := range list {
				allUniqueKeys[item.Key] = true
			}
		}
	}

	type keyCoverage struct {
		Key          string   `json:"key"`
		Development  bool     `json:"development"`
		Staging      bool     `json:"staging"`
		Production   bool     `json:"production"`
		Environments []string `json:"environments"`
	}

	keys := make([]string, 0, len(allUniqueKeys))
	for k := range allUniqueKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	envCounts := make(map[string]int, len(envs))
	missing := make(map[string][]string, len(envs))
	for _, env := range envs {
		envCounts[env] = len(lists[env])
		missing[env] = []string{}
	}

	coverage := make([]keyCoverage, 0, len(keys))
	fullyCoveredCount := 0
	partiallyCoveredCount := 0

	for _, k := range keys {
		presentSet := make(map[string]bool, len(envs))
		present := make([]string, 0, len(envs))
		for _, env := range envs {
			for _, item := range lists[env] {
				if item.Key == k {
					presentSet[env] = true
					present = append(present, env)
					break
				}
			}
		}
		for _, env := range envs {
			if !presentSet[env] {
				missing[env] = append(missing[env], k)
			}
		}

		coverage = append(coverage, keyCoverage{
			Key:          k,
			Development:  presentSet["development"],
			Staging:      presentSet["staging"],
			Production:   presentSet["production"],
			Environments: present,
		})

		if len(present) == len(envs) {
			fullyCoveredCount++
		} else {
			partiallyCoveredCount++
		}
	}

	return jsonResult(map[string]interface{}{
		"coverage":     coverage,
		"missing":      missing,
		"environments": envs,
		"summary": map[string]interface{}{
			"total_unique_keys": len(allUniqueKeys),
			"fully_covered":     fullyCoveredCount,
			"partially_covered": partiallyCoveredCount,
			"env_counts":        envCounts,
		},
	})
}

func (s *Server) handleGetStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	pc, _ := config.LoadProjectConfig()

	// --- Authentication & Session ---
	sessionData := map[string]interface{}{}
	tokens, _ := config.LoadTokens()
	if tokens != nil {
		if tokens.ExpiresAt != "" {
			sessionData["expires_at"] = tokens.ExpiresAt
			if exp, err := time.Parse(time.RFC3339, tokens.ExpiresAt); err == nil {
				timeUntil := time.Until(exp)
				if timeUntil <= 0 {
					sessionData["status"] = "expired"
				} else if timeUntil < 5*time.Minute {
					sessionData["status"] = "expiring_soon"
				} else {
					sessionData["status"] = "active"
				}
				sessionData["expires_in_seconds"] = int(timeUntil.Seconds())
			}
		}
		sessionData["refresh_token_available"] = tokens.RefreshToken != ""
	}

	// --- Workspace ---
	wsID := config.GetSelectedWorkspaceID()
	global, _ := config.LoadGlobalConfig()
	workspaceData := map[string]interface{}{}
	if wsID != "" && global != nil {
		if ws, ok := global.Workspaces[wsID]; ok {
			workspaceData["id"] = wsID
			workspaceData["name"] = ws.Name
			workspaceData["type"] = ws.Type
			workspaceData["role"] = ws.Role
		}
	}

	// --- Proxy ---
	proxyRunning := false
	var proxyPid, proxyPort int
	var proxyUptime string

	home, err := os.UserHomeDir()
	if err == nil {
		pidPath := filepath.Join(home, ".agentsecrets", "proxy.pid")
		if data, err := os.ReadFile(pidPath); err == nil {
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) >= 3 {
				pid, _ := strconv.Atoi(lines[0])
				ts, _ := strconv.ParseInt(lines[1], 10, 64)
				port, _ := strconv.Atoi(lines[2])

				if pid > 0 {
					p, err := os.FindProcess(pid)
					if err == nil {
						sigErr := p.Signal(syscall.Signal(0))
						if sigErr == nil {
							proxyRunning = true
							proxyPid = pid
							proxyPort = port
							proxyUptime = time.Since(time.Unix(ts, 0)).Round(time.Second).String()
						}
					}
				}
			}
		}
	}

	activeEnv, envSource := config.ResolveEnvironmentWithSource()

	// --- Project --- (full detail from the project file when launched in a
	// repo; globally-selected IDs otherwise, so headless MCP servers still
	// report which project they serve)
	projectData := map[string]interface{}{}
	if pc != nil && pc.ProjectID != "" {
		projectData["id"] = pc.ProjectID
		projectData["name"] = pc.ProjectName
		projectData["workspace_id"] = pc.WorkspaceID
		projectData["workspace_name"] = pc.WorkspaceName
		projectData["environment"] = pc.Environment
	} else if projectID, workspaceID := config.ResolveProjectContext(); projectID != "" {
		projectData["id"] = projectID
		projectData["workspace_id"] = workspaceID
	}

	// --- Secrets Sync (matches CLI DiffCached) ---
	secretsData := map[string]interface{}{}
	if pc != nil && pc.ProjectID != "" {
		svc := s.getSecretsService()
		diff, diffErr := svc.DiffCached("", "")
		if diffErr == nil {
			syncedCount := len(diff.Unchanged)
			unsyncedCount := len(diff.Added) + len(diff.Changed) + len(diff.Removed)
			secretsData["synced"] = syncedCount
			secretsData["unsynced"] = unsyncedCount
			secretsData["total"] = syncedCount + unsyncedCount
			secretsData["in_sync"] = unsyncedCount == 0
		} else {
			secretsData["error"] = diffErr.Error()
		}
	}

	// --- Activity ---
	activityData := map[string]interface{}{}
	if pc != nil {
		lastPush := "never"
		lastPull := "never"
		if pc.LastPush != "" {
			lastPush = pc.LastPush
		}
		if pc.LastPull != "" {
			lastPull = pc.LastPull
		}
		activityData["last_push"] = lastPush
		activityData["last_pull"] = lastPull
	}

	return jsonResult(map[string]interface{}{
		"authenticated": config.IsAuthenticated(),
		"email":         config.GetEmail(),
		"session":       sessionData,
		"workspace":     workspaceData,
		"project":       projectData,
		"proxy": map[string]interface{}{
			"running": proxyRunning,
			"pid":     proxyPid,
			"port":    proxyPort,
			"uptime":  proxyUptime,
		},
		"keychain_auth": map[string]interface{}{
			"configured": keychainauth.IsFullyConfigured(),
		},
		"environment": map[string]interface{}{
			"active": activeEnv,
			"source": envSource,
		},
		"secrets":     secretsData,
		"activity":    activityData,
		"permissions": s.TierReport(),
	})
}

func (s *Server) handleGetEnvironment(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	env, source := config.ResolveEnvironmentWithSource()
	pc, _ := config.LoadProjectConfig()

	projectData := map[string]interface{}{}
	if pc != nil && pc.ProjectID != "" {
		projectData = map[string]interface{}{
			"id":   pc.ProjectID,
			"name": pc.ProjectName,
		}
	} else if projectID, _ := config.ResolveProjectContext(); projectID != "" {
		projectData = map[string]interface{}{"id": projectID}
	}

	return jsonResult(map[string]interface{}{
		"environment":           env,
		"source":                source,
		"project":               projectData,
		"standard_environments": config.StandardEnvironments,
		"environment_name_rule": config.EnvironmentNameRule,
	})
}

func (s *Server) handleDiffSecrets(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	envParam, _ := args["environment"].(string)

	env := envParam
	if env == "" {
		env = config.ResolveEnvironment()
	}
	env, err := config.ParseEnvironment(env)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	svc := s.getSecretsService()
	diff, err := svc.Diff("", env)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("diff failed: %v", err)), nil
	}

	// Redact values from Changed map to ensure zero leaks
	redactedChanged := make(map[string][2]string)
	for k := range diff.Changed {
		redactedChanged[k] = [2]string{"[redacted]", "[redacted]"}
	}

	localCount := len(diff.Added) + len(diff.Unchanged) + len(diff.Changed)
	cloudCount := len(diff.Removed) + len(diff.Unchanged) + len(diff.Changed)

	return jsonResult(map[string]interface{}{
		"environment": env,
		"added":       diff.Added,
		"removed":     diff.Removed,
		"changed":     redactedChanged,
		"unchanged":   diff.Unchanged,
		"summary": map[string]interface{}{
			"total_local": localCount,
			"total_cloud": cloudCount,
			"in_sync":     len(diff.Added) == 0 && len(diff.Removed) == 0 && len(diff.Changed) == 0,
		},
	})
}

func (s *Server) handleDiffEnvironments(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	source, _ := args["source"].(string)
	target, _ := args["target"].(string)

	if source == "" || target == "" {
		return mcp.NewToolResultError("missing required parameters: source and target"), nil
	}

	source, err := config.ParseEnvironment(source)
	if err != nil {
		return mcp.NewToolResultError("source environment: " + err.Error()), nil
	}
	target, err = config.ParseEnvironment(target)
	if err != nil {
		return mcp.NewToolResultError("target environment: " + err.Error()), nil
	}

	svc := s.getSecretsService()
	srcList, err := svc.ListForEnv(source)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to list keys for source: %v", err)), nil
	}

	tgtList, err := svc.ListForEnv(target)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to list keys for target: %v", err)), nil
	}

	srcSet := make(map[string]bool)
	for _, item := range srcList {
		srcSet[item.Key] = true
	}

	tgtSet := make(map[string]bool)
	for _, item := range tgtList {
		tgtSet[item.Key] = true
	}

	onlyInSource := []string{}
	onlyInTarget := []string{}
	inBoth := []string{}

	for k := range srcSet {
		if tgtSet[k] {
			inBoth = append(inBoth, k)
		} else {
			onlyInSource = append(onlyInSource, k)
		}
	}

	for k := range tgtSet {
		if !srcSet[k] {
			onlyInTarget = append(onlyInTarget, k)
		}
	}

	return jsonResult(map[string]interface{}{
		"source":         source,
		"target":         target,
		"only_in_source": onlyInSource,
		"only_in_target": onlyInTarget,
		"in_both":        inBoth,
		"summary": map[string]interface{}{
			"source_count": len(srcList),
			"target_count": len(tgtList),
			"shared":       len(inBoth),
			"drift_count":  len(onlyInSource) + len(onlyInTarget),
		},
	})
}

func (s *Server) handleGetProxyLogs(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	keyName, _ := args["key_name"].(string)
	domain, _ := args["domain"].(string)
	limitStr, _ := args["limit"].(string)
	sinceStr, _ := args["since"].(string)

	limit := 20
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	var since time.Time
	if sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = t
		}
	}

	logSvc, err := log.NewService(s.getAPIClient(), nil)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to init log service: %v", err)), nil
	}
	defer logSvc.Close()

	projectID, _ := config.ResolveProjectContext()

	events, err := logSvc.QueryLocal(log.Filter{
		Credential: keyName,
		Domain:     domain,
		Since:      since,
		Limit:      limit,
		ProjectID:  projectID,
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to query logs: %v", err)), nil
	}

	return jsonResult(toSafeProxyLogs(events))
}

func (s *Server) handleGetBlockedRequests(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	limitStr, _ := args["limit"].(string)

	limit := 20
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	logSvc, err := log.NewService(s.getAPIClient(), nil)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to init log service: %v", err)), nil
	}
	defer logSvc.Close()

	projectID, _ := config.ResolveProjectContext()

	events, err := logSvc.QueryLocal(log.Filter{
		Blocked:   true,
		Limit:     limit,
		ProjectID: projectID,
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to query blocked logs: %v", err)), nil
	}

	return jsonResult(toSafeProxyLogs(events))
}

func (s *Server) handleGetRedactionEvents(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	limitStr, _ := args["limit"].(string)

	limit := 20
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	logSvc, err := log.NewService(s.getAPIClient(), nil)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to init log service: %v", err)), nil
	}
	defer logSvc.Close()

	projectID, _ := config.ResolveProjectContext()

	events, err := logSvc.QueryLocal(log.Filter{
		Redacted:  true,
		Limit:     limit,
		ProjectID: projectID,
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to query redacted logs: %v", err)), nil
	}

	return jsonResult(toSafeProxyLogs(events))
}

func (s *Server) handleGetAuditSummary(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	logSvc, err := log.NewService(s.getAPIClient(), nil)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to init log service: %v", err)), nil
	}
	defer logSvc.Close()

	projectID, _ := config.ResolveProjectContext()

	events, err := logSvc.QueryLocal(log.Filter{
		Limit:     1000,
		ProjectID: projectID,
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to retrieve logs: %v", err)), nil
	}

	totalCalls := len(events)
	uniqueDomains := make(map[string]bool)
	uniqueCredentials := make(map[string]bool)
	blockedCount := 0
	redactedCount := 0

	envCounts := make(map[string]int)
	statusClassCounts := map[string]int{
		"2xx":   0,
		"3xx":   0,
		"4xx":   0,
		"5xx":   0,
		"other": 0,
	}

	for _, ev := range events {
		if ev.Domain != "" {
			uniqueDomains[ev.Domain] = true
		}
		for _, key := range ev.SecretKeys {
			uniqueCredentials[key] = true
		}
		if ev.Status == "BLOCKED" {
			blockedCount++
		}
		if ev.Redacted {
			redactedCount++
		}
		if ev.Environment != "" {
			envCounts[ev.Environment]++
		}

		sc := ev.StatusCode
		switch {
		case sc >= 200 && sc < 300:
			statusClassCounts["2xx"]++
		case sc >= 300 && sc < 400:
			statusClassCounts["3xx"]++
		case sc >= 400 && sc < 500:
			statusClassCounts["4xx"]++
		case sc >= 500 && sc < 600:
			statusClassCounts["5xx"]++
		default:
			statusClassCounts["other"]++
		}
	}

	return jsonResult(map[string]interface{}{
		"total_calls":        totalCalls,
		"unique_domains":     len(uniqueDomains),
		"unique_credentials": len(uniqueCredentials),
		"blocked_requests":   blockedCount,
		"redacted_events":    redactedCount,
		"environment_calls":  envCounts,
		"status_classes":     statusClassCounts,
	})
}

func (s *Server) handleGetAgentIdentity(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	agentTokenSet := os.Getenv("AS_AGENT_TOKEN") != ""
	keychainConfigured := keychainauth.IsFullyConfigured()
	authenticated := config.IsAuthenticated()
	email := config.GetEmail()

	return jsonResult(map[string]interface{}{
		"agent_token_set":     agentTokenSet,
		"keychain_configured": keychainConfigured,
		"authenticated":       authenticated,
		"email":               email,
	})
}

func (s *Server) handleGetAllowlist(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_, workspaceID := config.ResolveProjectContext()
	if workspaceID == "" {
		return mcp.NewToolResultError("no workspace configured — run 'agentsecrets init' first"), nil
	}

	wsSvc := s.getWorkspaceService()
	domainsResp, err := wsSvc.ListAllowlist(workspaceID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to fetch allowlist: %v", err)), nil
	}

	domainNames := make([]string, len(domainsResp))
	for i, d := range domainsResp {
		domainNames[i] = d.Domain
	}

	return jsonResult(map[string]interface{}{
		"workspace_id": workspaceID,
		"domains":      domainNames,
		"count":        len(domainNames),
	})
}

func (s *Server) handleCheckDomain(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	domain, _ := args["domain"].(string)
	if domain == "" {
		return mcp.NewToolResultError("missing required parameter: domain"), nil
	}

	_, workspaceID := config.ResolveProjectContext()
	if workspaceID == "" {
		return mcp.NewToolResultError("no workspace configured — run 'agentsecrets init' first"), nil
	}

	wsSvc := s.getWorkspaceService()
	domainsResp, err := wsSvc.ListAllowlist(workspaceID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to fetch allowlist: %v", err)), nil
	}

	allowed := false
	check := strings.ToLower(strings.TrimSpace(domain))
	domainList := []string{}
	for _, d := range domainsResp {
		domainList = append(domainList, d.Domain)
		if strings.ToLower(strings.TrimSpace(d.Domain)) == check {
			allowed = true
		}
	}

	res := map[string]interface{}{
		"domain":    domain,
		"allowed":   allowed,
		"allowlist": domainList,
	}

	if !allowed {
		res["add_command"] = fmt.Sprintf("agentsecrets workspace allowlist add %s", domain)
	}

	return jsonResult(res)
}

func (s *Server) handleListAgentTokens(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_, workspaceID := config.ResolveProjectContext()
	if workspaceID == "" {
		return mcp.NewToolResultError("no workspace configured — run 'agentsecrets init' first"), nil
	}

	svc := agents.NewService(s.getAPIClient())
	agentList, err := svc.List(workspaceID, "")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to list agents: %v", err)), nil
	}

	type agentDetails struct {
		Agent  agents.Agent   `json:"agent"`
		Tokens []agents.Token `json:"tokens"`
	}

	details := []agentDetails{}
	for _, ag := range agentList {
		toks, err := svc.TokenList(workspaceID, ag.ID)
		if err != nil {
			toks = []agents.Token{}
		}
		details = append(details, agentDetails{
			Agent:  ag,
			Tokens: toks,
		})
	}

	return jsonResult(details)
}
