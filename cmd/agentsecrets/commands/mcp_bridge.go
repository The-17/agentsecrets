package commands

// AgentSecrets MCP bridge helper.
//
// `agentsecrets mcp bridge <verb> [json-args]` is the machine-readable
// counterpart to the human CLI. It exists so out-of-process clients —
// notably the TypeScript MCP bridge (`integrations/mcp`, `npx
// @agentsecrets/mcp`) — can delegate privileged local operations (OS
// keychain secrets, proxy session token, token refresh, E2EE workspace
// keys) without reimplementing them and without parsing human-readable
// tables.
//
// Protocol (v1, stable):
//   - argv:  mcp bridge <verb> [<json-args>]. When <json-args> is absent,
//     JSON is read from stdin when piped, otherwise "{}".
//   - stdout: exactly one JSON object per invocation:
//       {"ok": true, "data": ...}   on success
//       {"ok": false, "error": "..."} on handled failure (exit code still 0)
//     Non-zero exit codes are reserved for crashes and usage errors.
//   - stderr: diagnostics and warnings only. Never JSON, never secrets.
//   - Zero-knowledge: no verb returns secret VALUES or tokens, except
//     agent.token_issue which returns a one-time token by design (the
//     caller must store it immediately and never log it).
//
// Every verb calls the same services as the interactive commands and the
// Go MCP server — no new product logic lives here.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/agents"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keychainauth"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/log"
	"github.com/The-17/agentsecrets/pkg/projects"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/telemetry"
)

var mcpBridgeCmd = &cobra.Command{
	Use:   "bridge <verb> [json-args]",
	Short: "Machine-readable JSON helper for the MCP bridge (local mode)",
	Long: `Execute one privileged local operation and print a JSON envelope to stdout.

Verbs: ping, status, auth.export,
  secrets.list, secrets.set, secrets.delete, secrets.pull, secrets.push, secrets.diff,
  proxy.call, proxy.status,
  project.list, project.create, project.use, project.update, project.delete,
  workspace.list, workspace.create, workspace.switch, workspace.members,
  agent.list, agent.delete, agent.token_issue,
  logs.list, logs.summary, logs.detail

Args are a single JSON object (argv or stdin). Stdout is always exactly one
JSON envelope: {"ok":true,"data":...} or {"ok":false,"error":"..."}.`,
	Args: cobra.MinimumNArgs(1),
	RunE: runMCPBridge,
}

func init() {
	mcpCmd.AddCommand(mcpBridgeCmd)
}

// bridgeVerbs is the advertised capability set (also returned by ping).
var bridgeVerbs = []string{
	"ping", "status", "auth.export",
	"secrets.list", "secrets.set", "secrets.delete", "secrets.pull", "secrets.push", "secrets.diff",
	"proxy.call", "proxy.status",
	"project.list", "project.create", "project.use", "project.update", "project.delete",
	"workspace.list", "workspace.create", "workspace.switch", "workspace.members",
	"agent.list", "agent.delete", "agent.token_issue",
	"logs.list", "logs.summary", "logs.detail",
}

// envelope helpers -----------------------------------------------------------

func bridgeOK(data interface{}) {
	out, _ := json.Marshal(map[string]interface{}{"ok": true, "data": data})
	fmt.Println(string(out))
}

func bridgeErr(format string, args ...interface{}) {
	out, _ := json.Marshal(map[string]interface{}{"ok": false, "error": fmt.Sprintf(format, args...)})
	fmt.Println(string(out))
}

// runMCPBridge is the single entrypoint: parse verb+args, dispatch, envelope.
func runMCPBridge(cmd *cobra.Command, args []string) error {
	if err := keychainauth.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: keychain-auth initialization failed: %v\n", err)
	}

	verb := args[0]
	rawArgs, err := bridgeInput(args[1:])
	if err != nil {
		return fmt.Errorf("invalid JSON args: %w", err)
	}

	// Scope enforcement is per-verb (see expect helpers below): verbs that
	// read the directory binding or the selected workspace verify the
	// caller's expect_project/expect_workspace declarations; verbs that
	// honor explicit scope directly need no check.
	handler, known := bridgeDispatch[verb]
	if !known {
		return fmt.Errorf("unknown bridge verb %q (verbs: %s)", verb, strings.Join(bridgeVerbs, ", "))
	}
	// Telemetry: mark the bridge integration (per-verb counts come from the
	// TS caller; command/sync flushing rides the shared root preamble).
	telemetry.RecordIntegration("mcp-bridge")
	if err := handler(rawArgs); err != nil {
		bridgeErr("%v", err)
		return nil
	}
	return nil
}

// bridgeInput decodes the JSON argument object from argv or piped stdin.
func bridgeInput(rest []string) (map[string]interface{}, error) {
	var raw string
	if len(rest) > 0 {
		raw = strings.Join(rest, " ")
	} else {
		fi, err := os.Stdin.Stat()
		if err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return nil, err
			}
			raw = string(data)
		}
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]interface{}{}, nil
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

// arg helpers -----------------------------------------------------------------

func argStr(a map[string]interface{}, key string) string {
	v, _ := a[key].(string)
	return v
}

func argBool(a map[string]interface{}, key string) bool {
	v, _ := a[key].(bool)
	return v
}

func argInt(a map[string]interface{}, key string, def int) int {
	switch v := a[key].(type) {
	case float64:
		if v > 0 {
			return int(v)
		}
	case int:
		if v > 0 {
			return v
		}
	}
	return def
}

func requireStr(a map[string]interface{}, key string) (string, error) {
	v := argStr(a, key)
	if v == "" {
		return "", fmt.Errorf("missing required parameter: %s", key)
	}
	return v, nil
}

func requireConfirm(a map[string]interface{}, op string) error {
	if !argBool(a, "confirm") {
		return fmt.Errorf("%s is destructive: pass {\"confirm\": true} to proceed", op)
	}
	return nil
}

// --- Caller-declared scope (expect_*) ---------------------------------------
// The TS bridge forwards the model's requested project/workspace as
// expect_project/expect_workspace (id or name). Verbs that derive scope
// implicitly (directory binding, selected workspace, running daemon) verify
// the declaration; verbs that route explicitly need no check.

// bindingScope describes the directory's project binding (nil when none).
type bindingScope struct {
	projectID, projectName, workspaceID, workspaceName string
}

func loadBindingScope() *bindingScope {
	pc, err := config.LoadProjectConfig()
	if err != nil || pc == nil || pc.ProjectID == "" {
		return nil
	}
	return &bindingScope{projectID: pc.ProjectID, projectName: pc.ProjectName, workspaceID: pc.WorkspaceID, workspaceName: pc.WorkspaceName}
}

func matchScopeRef(expect, id, name string) bool {
	if expect == "" {
		return true
	}
	return expect == id || (name != "" && expect == name)
}

func displayScopeName(name, id string) string {
	if name != "" {
		return name
	}
	return id
}

func cachedWorkspaceName(id string) string {
	if cfg, err := config.LoadGlobalConfig(); err == nil && cfg != nil {
		if ws, ok := cfg.Workspaces[id]; ok {
			return ws.Name
		}
	}
	return ""
}

// expectBindingProject fails when the caller named a project that is not
// this directory's bound project. For verbs that read the binding.
func expectBindingProject(a map[string]interface{}) error {
	expect := argStr(a, "expect_project")
	if expect == "" {
		return nil
	}
	b := loadBindingScope()
	if b == nil {
		return nil // no binding: the verb fails clearly on its own
	}
	if !matchScopeRef(expect, b.projectID, b.projectName) {
		return fmt.Errorf("scope mismatch: caller expects project %q but this directory is bound to %q — pass that project's directory via `path`", expect, displayScopeName(b.projectName, b.projectID))
	}
	return nil
}

// expectBindingWorkspace fails on workspace disagreement with the binding.
func expectBindingWorkspace(a map[string]interface{}) error {
	expect := argStr(a, "expect_workspace")
	if expect == "" {
		return nil
	}
	b := loadBindingScope()
	if b == nil || b.workspaceID == "" {
		return nil
	}
	wsName := b.workspaceName
	if wsName == "" {
		wsName = cachedWorkspaceName(b.workspaceID)
	}
	if !matchScopeRef(expect, b.workspaceID, wsName) {
		return fmt.Errorf("scope mismatch: caller expects workspace %q but this directory is bound to workspace %q — pass that project's directory via `path`", expect, displayScopeName(wsName, b.workspaceID))
	}
	return nil
}

// withExpectWorkspace honors an explicit workspace for verbs routed via the
// selected workspace: temporarily select it for fn, then restore.
func withExpectWorkspace(a map[string]interface{}, fn func() error) error {
	expect := argStr(a, "expect_workspace")
	if expect == "" {
		return fn()
	}
	wsID := expect
	if cfg, err := config.LoadGlobalConfig(); err == nil && cfg != nil {
		for id, ws := range cfg.Workspaces {
			if id == expect || ws.Name == expect {
				wsID = id
				break
			}
		}
	}
	prev := config.GetSelectedWorkspaceID()
	if wsID == prev {
		return fn()
	}
	if err := config.SetSelectedWorkspaceID(wsID); err != nil {
		return err
	}
	defer func() { _ = config.SetSelectedWorkspaceID(prev) }()
	return fn()
}

// checkDaemonProject fails when a RUNNING daemon proxy serves a different
// project than this directory's binding — the daemon's start project, not
// the caller's cwd, decides which secrets resolve.
func checkDaemonProject() error {
	_, port, running := proxy.IsProxyRunning()
	if !running {
		return nil // transient engine uses this directory: exact by construction
	}
	b := loadBindingScope()
	if b == nil {
		return nil
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
	if err != nil {
		return nil // unreachable: CallViaProxy surfaces it
	}
	defer resp.Body.Close()
	var health struct {
		Project string `json:"project"`
	}
	if json.NewDecoder(resp.Body).Decode(&health) != nil || health.Project == "" {
		return nil
	}
	if health.Project != b.projectID {
		return fmt.Errorf("scope mismatch: running proxy serves project %q but this directory binds %q — run `agentsecrets proxy start` in the target directory or pass its `path`", health.Project, displayScopeName(b.projectName, b.projectID))
	}
	return nil
}

// switchBridgeEnv mirrors the Go MCP write tools: when an explicit,
// valid environment differs from the active one, persist it to the
// project + global config before operating. Returns the active env.
func switchBridgeEnv(envParam string) (string, error) {
	env := envParam
	if env == "" {
		return config.ResolveEnvironment(), nil
	}
	env, err := config.ParseEnvironment(env)
	if err != nil {
		return "", err
	}
	if pc, err := config.LoadProjectConfig(); err == nil && pc != nil && pc.Environment != env {
		pc.Environment = env
		if err := config.SaveProjectConfig(pc); err != nil {
			return "", fmt.Errorf("failed to update environment: %w", err)
		}
		if gc, err := config.LoadGlobalConfig(); err == nil && gc != nil {
			gc.SelectedEnvironment = env
			_ = config.SaveGlobalConfig(gc)
		}
	}
	return env, nil
}

func bridgeProject() (*config.ProjectConfig, error) {
	pc, err := config.LoadProjectConfig()
	if err != nil || pc == nil || pc.ProjectID == "" {
		return nil, fmt.Errorf("no project configured in current directory — run 'agentsecrets init' or 'agentsecrets project use <name>' first")
	}
	return pc, nil
}

func bridgeWorkspaceID(a map[string]interface{}, pc *config.ProjectConfig) string {
	if v := argStr(a, "workspace"); v != "" {
		return v
	}
	if pc != nil && pc.WorkspaceID != "" {
		return pc.WorkspaceID
	}
	return config.GetSelectedWorkspaceID()
}

// dispatch table ---------------------------------------------------------------

type bridgeHandler func(a map[string]interface{}) error

var bridgeDispatch = map[string]bridgeHandler{
	"ping":              bridgePing,
	"status":            bridgeStatus,
	"auth.export":       bridgeAuthExport,
	"secrets.list":      bridgeSecretsList,
	"secrets.set":       bridgeSecretsSet,
	"secrets.delete":    bridgeSecretsDelete,
	"secrets.pull":      bridgeSecretsPull,
	"secrets.push":      bridgeSecretsPush,
	"secrets.diff":      bridgeSecretsDiff,
	"proxy.call":        bridgeProxyCall,
	"proxy.status":      bridgeProxyStatus,
	"project.list":      bridgeProjectList,
	"project.create":    bridgeProjectCreate,
	"project.use":       bridgeProjectUse,
	"project.update":    bridgeProjectUpdate,
	"project.delete":    bridgeProjectDelete,
	"workspace.list":    bridgeWorkspaceList,
	"workspace.create":  bridgeWorkspaceCreate,
	"workspace.switch":  bridgeWorkspaceSwitch,
	"workspace.members": bridgeWorkspaceMembers,
	"agent.list":        bridgeAgentList,
	"agent.delete":      bridgeAgentDelete,
	"agent.token_issue": bridgeAgentTokenIssue,
	"logs.list":         bridgeLogsList,
	"logs.summary":      bridgeLogsSummary,
	"logs.detail":       bridgeLogsDetail,
}

// ping / status -----------------------------------------------------------------

func bridgePing(a map[string]interface{}) error {
	bridgeOK(map[string]interface{}{
		"version":   Version,
		"protocol":  "mcp-bridge-v1",
		"verbs":     bridgeVerbs,
		"keychain":  keychainauth.IsFullyConfigured(),
	})
	return nil
}

// bridgeSafeStatus mirrors the Go MCP get_status tool: session/workspace/
// project/proxy/environment metadata. Tokens and keys are never included.
func bridgeStatus(a map[string]interface{}) error {
	pc, _ := config.LoadProjectConfig()

	sessionData := map[string]interface{}{}
	if tokens, _ := config.LoadTokens(); tokens != nil {
		if tokens.ExpiresAt != "" {
			sessionData["expires_at"] = tokens.ExpiresAt
		}
		sessionData["refresh_token_available"] = tokens.RefreshToken != ""
	}

	workspaceData := map[string]interface{}{}
	if wsID := config.GetSelectedWorkspaceID(); wsID != "" {
		if global, _ := config.LoadGlobalConfig(); global != nil {
			if ws, ok := global.Workspaces[wsID]; ok {
				workspaceData["id"] = wsID
				workspaceData["name"] = ws.Name
				workspaceData["type"] = ws.Type
				workspaceData["role"] = ws.Role
			}
		}
	}

	pid, port, running := proxy.IsProxyRunning()

	activeEnv, envSource := config.ResolveEnvironmentWithSource()

	projectData := map[string]interface{}{}
	if pc != nil && pc.ProjectID != "" {
		projectData["id"] = pc.ProjectID
		projectData["name"] = pc.ProjectName
		projectData["workspace_id"] = pc.WorkspaceID
		projectData["workspace_name"] = pc.WorkspaceName
		projectData["environment"] = pc.Environment
	}

	bridgeOK(map[string]interface{}{
		"authenticated": config.IsAuthenticated(),
		"email":         config.GetEmail(),
		"session":       sessionData,
		"workspace":     workspaceData,
		"project":       projectData,
		"proxy": map[string]interface{}{
			"running": running,
			"pid":     pid,
			"port":    port,
		},
		"keychain_auth": map[string]interface{}{
			"configured": keychainauth.IsFullyConfigured(),
		},
		"environment": map[string]interface{}{
			"active": activeEnv,
			"source": envSource,
		},
	})
	return nil
}

// bridgeAuthExport prints the current CLI session tokens as JSON so the
// operator can save them to a 0600 file for headless clients:
//
//	agentsecrets mcp bridge auth.export > ~/.agentsecrets/mcp-token
//	chmod 600 ~/.agentsecrets/mcp-token
//
// The MCP bridge then reads them via AGENTSECRETS_TOKEN_FILE. The token
// travels terminal-to-file and NEVER through the LLM or MCP config.
// Redirect stdout to a file; do not copy tokens into chat.
func bridgeAuthExport(a map[string]interface{}) error {
	if !config.IsAuthenticated() {
		return fmt.Errorf("not logged in — run 'agentsecrets login' first")
	}
	tokens, err := config.LoadTokens()
	if err != nil || tokens == nil || tokens.AccessToken == "" {
		return fmt.Errorf("no session tokens available — run 'agentsecrets login' first")
	}
	bridgeOK(map[string]interface{}{
		"email":         config.GetEmail(),
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"expires_at":    tokens.ExpiresAt,
		"warning":       "Secret session credentials. Redirect stdout to a 0600 file (AGENTSECRETS_TOKEN_FILE). Never paste into chat, tickets, or MCP client config.",
	})
	return nil
}

// secrets ------------------------------------------------------------------------

func bridgeSecretsList(a map[string]interface{}) error {
	if err := expectBindingProject(a); err != nil {
		return err
	}
	if err := expectBindingWorkspace(a); err != nil {
		return err
	}
	envParam := argStr(a, "environment")
	remote := argBool(a, "remote")

	env := envParam
	if env == "" {
		env = config.ResolveEnvironment()
	}
	normalized, err := config.ParseEnvironment(env)
	if err != nil {
		return err
	}
	env = normalized
	pc, err := bridgeProject()
	if err != nil {
		return err
	}

	type keyInfo struct {
		Key       string `json:"key"`
		UpdatedAt string `json:"updated_at,omitempty"`
	}
	keys := []keyInfo{}
	if remote {
		list, err := app.Secrets().ListForEnv(env)
		if err != nil {
			return fmt.Errorf("remote list failed: %w", err)
		}
		for _, item := range list {
			keys = append(keys, keyInfo{Key: item.Key, UpdatedAt: item.UpdatedAt})
		}
	} else {
		names, _ := keyring.ListProjectKeyNames(pc.ProjectID, env)
		for _, n := range names {
			keys = append(keys, keyInfo{Key: n})
		}
	}
	if keys == nil {
		keys = []keyInfo{}
	}
	source := "local_keyring"
	if remote {
		source = "api"
	}
	bridgeOK(map[string]interface{}{
		"environment": env,
		"project_id":  pc.ProjectID,
		"keys":        keys,
		"count":       len(keys),
		"source":      source,
	})
	return nil
}

func bridgeSecretsSet(a map[string]interface{}) error {
	if err := expectBindingProject(a); err != nil {
		return err
	}
	if err := expectBindingWorkspace(a); err != nil {
		return err
	}
	key, err := requireStr(a, "key")
	if err != nil {
		return err
	}
	value, err := requireStr(a, "value")
	if err != nil {
		return err
	}
	env, err := switchBridgeEnv(argStr(a, "environment"))
	if err != nil {
		return err
	}
	if err := app.Secrets().BatchSet(map[string]string{key: value}, env); err != nil {
		return err
	}
	bridgeOK(map[string]interface{}{"status": "success", "key": key, "environment": env})
	return nil
}

func bridgeSecretsDelete(a map[string]interface{}) error {
	if err := requireConfirm(a, "secrets.delete"); err != nil {
		return err
	}
	if err := expectBindingProject(a); err != nil {
		return err
	}
	if err := expectBindingWorkspace(a); err != nil {
		return err
	}
	key, err := requireStr(a, "key")
	if err != nil {
		return err
	}
	env, err := switchBridgeEnv(argStr(a, "environment"))
	if err != nil {
		return err
	}
	if err := app.Secrets().Delete(key); err != nil {
		return err
	}
	bridgeOK(map[string]interface{}{"status": "success", "key": key, "environment": env})
	return nil
}

func bridgeSecretsPull(a map[string]interface{}) error {
	if err := expectBindingProject(a); err != nil {
		return err
	}
	if err := expectBindingWorkspace(a); err != nil {
		return err
	}
	env, err := switchBridgeEnv(argStr(a, "environment"))
	if err != nil {
		return err
	}
	if err := app.Secrets().Pull(nil); err != nil {
		return fmt.Errorf("pull failed: %w", err)
	}
	bridgeOK(map[string]interface{}{"status": "success", "environment": env})
	return nil
}

func bridgeSecretsPush(a map[string]interface{}) error {
	if err := expectBindingProject(a); err != nil {
		return err
	}
	if err := expectBindingWorkspace(a); err != nil {
		return err
	}
	if err := app.Secrets().Push(); err != nil {
		return fmt.Errorf("push failed: %w", err)
	}
	bridgeOK(map[string]interface{}{"status": "success", "environment": config.ResolveEnvironment()})
	return nil
}

func bridgeSecretsDiff(a map[string]interface{}) error {
	if err := expectBindingProject(a); err != nil {
		return err
	}
	if err := expectBindingWorkspace(a); err != nil {
		return err
	}
	env := argStr(a, "environment")
	if env == "" {
		env = config.ResolveEnvironment()
	}
	normalized, err := config.ParseEnvironment(env)
	if err != nil {
		return err
	}
	env = normalized
	diff, err := app.Secrets().Diff("", env)
	if err != nil {
		return fmt.Errorf("diff failed: %w", err)
	}
	// Values never leave this process: report changed keys by name only.
	changed := []string{}
	for k := range diff.Changed {
		changed = append(changed, k)
	}
	sort.Strings(changed)
	bridgeOK(map[string]interface{}{
		"environment": env,
		"added":       diff.Added,
		"removed":     diff.Removed,
		"changed":     changed,
		"unchanged":   diff.Unchanged,
		"in_sync":     len(diff.Added) == 0 && len(diff.Removed) == 0 && len(diff.Changed) == 0,
	})
	return nil
}

// proxy ---------------------------------------------------------------------------

// parseBridgeInjections mirrors pkg/mcp parseInjections: map entries of
// "style" or "style:target" to proxy.Injection structs.
func parseBridgeInjections(raw map[string]interface{}) ([]proxy.Injection, error) {
	var injections []proxy.Injection
	for spec, val := range raw {
		secretKey, ok := val.(string)
		if !ok || secretKey == "" {
			return nil, fmt.Errorf("injection value for %q must be a non-empty secret key name", spec)
		}
		inj := proxy.Injection{SecretKey: secretKey}
		parts := strings.SplitN(spec, ":", 2)
		style := strings.ToLower(parts[0])
		switch style {
		case "bearer", "basic":
			inj.Style = style
		case "header", "query", "body", "form":
			if len(parts) != 2 || parts[1] == "" {
				return nil, fmt.Errorf("%s injection requires a target — use %q format", style, style+":target_name")
			}
			inj.Style = style
			inj.Target = parts[1]
		default:
			return nil, fmt.Errorf("unknown injection style %q — valid: bearer, basic, header:name, query:param, body:path, form:field", spec)
		}
		injections = append(injections, inj)
	}
	return injections, nil
}

func bridgeProxyCall(a map[string]interface{}) error {
	if err := expectBindingProject(a); err != nil {
		return err
	}
	if err := expectBindingWorkspace(a); err != nil {
		return err
	}
	// A running daemon serves ITS start project, not this directory: verify.
	if err := checkDaemonProject(); err != nil {
		return err
	}
	targetURL, err := requireStr(a, "url")
	if err != nil {
		return err
	}
	method := argStr(a, "method")
	if method == "" {
		method = "GET"
	}
	rawInj, _ := a["injections"].(map[string]interface{})
	if len(rawInj) == 0 {
		return fmt.Errorf("missing required parameter: injections — provide at least one like {\"bearer\": \"SECRET_KEY\"}")
	}
	injections, err := parseBridgeInjections(rawInj)
	if err != nil {
		return err
	}
	headers := map[string]string{}
	if rawHeaders, _ := a["headers"].(map[string]interface{}); rawHeaders != nil {
		for k, v := range rawHeaders {
			if s, ok := v.(string); ok {
				headers[k] = s
			}
		}
	}
	var body []byte
	if bodyStr := argStr(a, "body"); bodyStr != "" {
		body = []byte(bodyStr)
	}
	agentID := argStr(a, "agent_id")
	if agentID == "" {
		// Parity with the Go MCP server: unattributed MCP calls log as "mcp",
		// which the engine counts in proxy_calls_mcp telemetry.
		agentID = "mcp"
	}
	result, err := proxy.CallViaProxy(proxy.CallRequest{
		TargetURL:  targetURL,
		Method:     method,
		Headers:    headers,
		Body:       body,
		Injections: injections,
		AgentID:    agentID,
	})
	if err != nil {
		return fmt.Errorf("API call failed: %w", err)
	}
	flatHeaders := map[string]string{}
	for k, vals := range result.Headers {
		flatHeaders[k] = strings.Join(vals, ", ")
	}
	bridgeOK(map[string]interface{}{
		"status_code": result.StatusCode,
		"headers":     flatHeaders,
		"body":        string(result.Body),
	})
	return nil
}

func bridgeProxyStatus(a map[string]interface{}) error {
	pid, port, running := proxy.IsProxyRunning()
	out := map[string]interface{}{"running": running, "pid": pid, "port": port}
	if running {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
		if err == nil {
			defer resp.Body.Close()
			var health map[string]interface{}
			if json.NewDecoder(resp.Body).Decode(&health) == nil {
				out["health"] = health
			}
		}
	}
	bridgeOK(out)
	return nil
}

// projects --------------------------------------------------------------------------

func bridgeProjectList(a map[string]interface{}) error {
	list, err := app.Projects().List()
	if err != nil {
		return err
	}
	if list == nil {
		list = []projects.Project{}
	}
	bridgeOK(map[string]interface{}{"projects": list})
	return nil
}

func bridgeProjectCreate(a map[string]interface{}) error {
	name, err := requireStr(a, "name")
	if err != nil {
		return err
	}
	return withExpectWorkspace(a, func() error {
		proj, err := app.Projects().Create(name, argStr(a, "description"))
		if err != nil {
			return err
		}
		bridgeOK(map[string]interface{}{"status": "success", "project": proj})
		return nil
	})
}

func bridgeProjectUse(a map[string]interface{}) error {
	name, err := requireStr(a, "name")
	if err != nil {
		return err
	}
	return withExpectWorkspace(a, func() error {
		proj, err := app.Projects().Use(name)
		if err != nil {
			return err
		}
		bridgeOK(map[string]interface{}{"status": "success", "project": proj})
		return nil
	})
}

func bridgeProjectUpdate(a map[string]interface{}) error {
	name, err := requireStr(a, "name")
	if err != nil {
		return err
	}
	newName := argStr(a, "newName")
	desc := argStr(a, "description")
	if newName == "" && desc == "" {
		return fmt.Errorf("nothing to update: provide newName and/or description")
	}
	return withExpectWorkspace(a, func() error {
		if err := app.Projects().Update(name, newName, desc); err != nil {
			return err
		}
		bridgeOK(map[string]interface{}{"status": "success", "name": name})
		return nil
	})
}

func bridgeProjectDelete(a map[string]interface{}) error {
	if err := requireConfirm(a, "project.delete"); err != nil {
		return err
	}
	name, err := requireStr(a, "name")
	if err != nil {
		return err
	}
	return withExpectWorkspace(a, func() error {
		if err := app.Projects().Delete(name); err != nil {
			return err
		}
		bridgeOK(map[string]interface{}{"status": "success", "name": name})
		return nil
	})
}

// workspaces --------------------------------------------------------------------------

func bridgeWorkspaceList(a map[string]interface{}) error {
	cfg, err := config.LoadGlobalConfig()
	if err != nil || cfg == nil {
		return fmt.Errorf("no AgentSecrets config found — run 'agentsecrets login' first")
	}
	type wsInfo struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Type     string `json:"type"`
		Role     string `json:"role"`
		Selected bool   `json:"selected"`
	}
	out := []wsInfo{}
	for id, ws := range cfg.Workspaces {
		out = append(out, wsInfo{ID: id, Name: ws.Name, Type: ws.Type, Role: ws.Role, Selected: id == cfg.SelectedWorkspaceID})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	bridgeOK(map[string]interface{}{"workspaces": out})
	return nil
}

func bridgeWorkspaceCreate(a map[string]interface{}) error {
	name, err := requireStr(a, "name")
	if err != nil {
		return err
	}
	if err := app.Workspaces().Create(name); err != nil {
		return err
	}
	bridgeOK(map[string]interface{}{"status": "success", "name": name, "workspace_id": config.GetSelectedWorkspaceID()})
	return nil
}

func bridgeWorkspaceSwitch(a map[string]interface{}) error {
	name, err := requireStr(a, "name")
	if err != nil {
		return err
	}
	cfg, err := config.LoadGlobalConfig()
	if err != nil || cfg == nil {
		return fmt.Errorf("no AgentSecrets config found — run 'agentsecrets login' first")
	}
	selectedID := ""
	for id, ws := range cfg.Workspaces {
		if ws.Name == name || id == name || (name == "personal" && strings.EqualFold(ws.Type, "personal")) {
			selectedID = id
			break
		}
	}
	if selectedID == "" {
		return fmt.Errorf("workspace %q not found", name)
	}
	if err := config.SetSelectedWorkspaceID(selectedID); err != nil {
		return fmt.Errorf("failed to update active workspace: %w", err)
	}
	bridgeOK(map[string]interface{}{"status": "success", "workspace_id": selectedID, "name": cfg.Workspaces[selectedID].Name})
	return nil
}

func bridgeWorkspaceMembers(a map[string]interface{}) error {
	pc, _ := config.LoadProjectConfig()
	wsID := bridgeWorkspaceID(a, pc)
	if wsID == "" {
		return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch <name>' first")
	}
	members, err := app.Workspaces().Members(wsID)
	if err != nil {
		return err
	}
	bridgeOK(map[string]interface{}{"workspace_id": wsID, "members": members})
	return nil
}

// agents -------------------------------------------------------------------------------

func bridgeAgentList(a map[string]interface{}) error {
	pc, _ := config.LoadProjectConfig()
	wsID := bridgeWorkspaceID(a, pc)
	if wsID == "" {
		return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch <name>' first")
	}
	projectID := argStr(a, "project")
	svc := app.Agents()
	list, err := svc.List(wsID, projectID)
	if err != nil {
		return fmt.Errorf("failed to list agents: %w", err)
	}
	type agentDetails struct {
		Agent  agents.Agent   `json:"agent"`
		Tokens []agents.Token `json:"tokens"`
	}
	details := []agentDetails{}
	for _, ag := range list {
		toks, err := svc.TokenList(wsID, ag.ID)
		if err != nil {
			toks = []agents.Token{}
		}
		details = append(details, agentDetails{Agent: ag, Tokens: toks})
	}
	bridgeOK(map[string]interface{}{"workspace_id": wsID, "agents": details})
	return nil
}

func resolveBridgeAgentID(svc interface {
	GetByName(workspaceID, name string) (*agents.Agent, error)
}, wsID, ref string) (string, error) {
	if strings.HasPrefix(ref, "areg_") {
		return ref, nil
	}
	ag, err := svc.GetByName(wsID, ref)
	if err != nil {
		return "", err
	}
	return ag.ID, nil
}

func bridgeAgentDelete(a map[string]interface{}) error {
	if err := requireConfirm(a, "agent.delete"); err != nil {
		return err
	}
	ref, err := requireStr(a, "agent")
	if err != nil {
		return err
	}
	pc, _ := config.LoadProjectConfig()
	wsID := bridgeWorkspaceID(a, pc)
	if wsID == "" {
		return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch <name>' first")
	}
	svc := app.Agents()
	id, err := resolveBridgeAgentID(svc, wsID, ref)
	if err != nil {
		return err
	}
	if err := svc.Delete(wsID, id); err != nil {
		return err
	}
	bridgeOK(map[string]interface{}{"status": "success", "agent": ref})
	return nil
}

func bridgeAgentTokenIssue(a map[string]interface{}) error {
	ref, err := requireStr(a, "agent")
	if err != nil {
		return err
	}
	pc, _ := config.LoadProjectConfig()
	wsID := bridgeWorkspaceID(a, pc)
	if wsID == "" {
		return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch <name>' first")
	}
	svc := app.Agents()
	id, err := resolveBridgeAgentID(svc, wsID, ref)
	if err != nil {
		return err
	}
	expiresDays, err := agents.ParseExpiresInDays(argStr(a, "expires_in"))
	if err != nil {
		return err
	}
	resp, err := svc.TokenIssue(wsID, id, agents.IssueTokenRequest{
		Environment:   argStr(a, "environment"),
		Label:         argStr(a, "label"),
		ExpiresInDays: expiresDays,
	})
	if err != nil {
		return err
	}
	bridgeOK(map[string]interface{}{
		"token_id":   resp.TokenID,
		"token":      resp.Token,
		"label":      resp.Label,
		"expires_at": resp.ExpiresAt,
		"one_time":   true,
		"warning":    "This token is shown ONCE. Store it immediately in a secret manager or AGENTSECRETS_TOKEN_FILE. Never log it.",
	})
	return nil
}

// resolveBridgeWorkspaceRef maps a workspace id-or-name to its id via the
// local cache, passing unknown values through for the server to reject.
func resolveBridgeWorkspaceRef(ref string) string {
	if cfg, err := config.LoadGlobalConfig(); err == nil && cfg != nil {
		for id, ws := range cfg.Workspaces {
			if id == ref || ws.Name == ref {
				return id
			}
		}
	}
	return ref
}

// logs ----------------------------------------------------------------------------------

// bridgeSafeLogs mirrors the Go MCP SafeProxyLog: metadata only, never values.
func bridgeSafeLogs(events []proxy.AuditEvent) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(events))
	for _, ev := range events {
		out = append(out, map[string]interface{}{
			"id":             ev.ID,
			"timestamp":      ev.Timestamp,
			"environment":    ev.Environment,
			"secret_keys":    ev.SecretKeys,
			"agent_id":       ev.AgentID,
			"identity_level": ev.IdentityLevel,
			"method":         ev.Method,
			"target_url":     ev.TargetURL,
			"domain":         ev.Domain,
			"status_code":    ev.StatusCode,
			"duration_ms":    ev.DurationMs,
			"status":         ev.Status,
			"reason":         ev.Reason,
			"redacted":       ev.Redacted,
		})
	}
	return out
}

func bridgeLogService() (*log.Service, error) {
	svc, err := log.NewService(app.API(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to init log service: %w", err)
	}
	return svc, nil
}

func bridgeLogsList(a map[string]interface{}) error {
	pc, _ := config.LoadProjectConfig()
	var wsID, projectID string
	if pc != nil {
		wsID = pc.WorkspaceID
		projectID = pc.ProjectID
	}
	if wsID == "" {
		wsID = config.GetSelectedWorkspaceID()
	}
	// Explicit workspace routes directly (server-authorized); no binding check.
	if v := argStr(a, "workspace"); v != "" {
		wsID = resolveBridgeWorkspaceRef(v)
	}
	if wsID == "" {
		return fmt.Errorf("no workspace configured — run 'agentsecrets init' first")
	}
	if v := argStr(a, "project"); v != "" {
		projectID = v
	}
	limit := argInt(a, "limit", 20)
	filter := log.Filter{
		Agent:     argStr(a, "identity"),
		Limit:     limit,
		ProjectID: projectID,
	}
	if days, ok := a["days"].(float64); ok && days > 0 {
		filter.Since = time.Now().Add(-time.Duration(days*24) * time.Hour)
	}
	svc, err := bridgeLogService()
	if err != nil {
		return err
	}
	defer svc.Close()
	events, err := svc.QueryRemote(wsID, filter)
	if err != nil {
		return fmt.Errorf("remote query failed: %w", err)
	}
	bridgeOK(map[string]interface{}{"workspace_id": wsID, "logs": bridgeSafeLogs(events)})
	return nil
}

func bridgeLogsSummary(a map[string]interface{}) error {
	pc, _ := config.LoadProjectConfig()
	var wsID, projectID string
	if pc != nil {
		wsID = pc.WorkspaceID
		projectID = pc.ProjectID
	}
	if wsID == "" {
		wsID = config.GetSelectedWorkspaceID()
	}
	if wsID == "" {
		wsID = config.GetSelectedWorkspaceID()
	}
	// Explicit workspace routes directly (server-authorized); no binding check.
	if v := argStr(a, "workspace"); v != "" {
		wsID = resolveBridgeWorkspaceRef(v)
	}
	filter := log.Filter{Limit: 1000, ProjectID: projectID}
	if days, ok := a["days"].(float64); ok && days > 0 {
		filter.Since = time.Now().Add(-time.Duration(days*24) * time.Hour)
	}
	svc, err := bridgeLogService()
	if err != nil {
		return err
	}
	defer svc.Close()
	events, err := svc.QueryRemote(wsID, filter)
	if err != nil {
		return fmt.Errorf("remote query failed: %w", err)
	}
	domains := map[string]bool{}
	creds := map[string]bool{}
	blocked, redacted := 0, 0
	for _, ev := range events {
		if ev.Domain != "" {
			domains[ev.Domain] = true
		}
		for _, k := range ev.SecretKeys {
			creds[k] = true
		}
		if ev.Status == "BLOCKED" {
			blocked++
		}
		if ev.Redacted {
			redacted++
		}
	}
	bridgeOK(map[string]interface{}{
		"workspace_id":       wsID,
		"total_calls":        len(events),
		"unique_domains":     len(domains),
		"unique_credentials": len(creds),
		"blocked_requests":   blocked,
		"redacted_events":    redacted,
	})
	return nil
}

func bridgeLogsDetail(a map[string]interface{}) error {
	logID, err := requireStr(a, "logId")
	if err != nil {
		// Accept snake_case too.
		logID, err = requireStr(a, "log_id")
		if err != nil {
			return err
		}
	}
	svc, err := bridgeLogService()
	if err != nil {
		return err
	}
	defer svc.Close()
	ev, err := svc.GetRemoteLog(logID)
	if err != nil {
		return fmt.Errorf("remote detail failed: %w", err)
	}
	bridgeOK(bridgeSafeLogs([]proxy.AuditEvent{*ev})[0])
	return nil
}
