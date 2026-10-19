package telemetry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
)

// Hook functions registered from other packages to avoid import cycles.
var (
	KeychainInitializedFunc func() bool
	LoadProjectIDFunc       func() string
	LoadGlobalConfigFunc    func() (string, string, string) // SelectedWorkspaceID, Email, WorkspaceType
	ResolveEnvironmentFunc  func() string
)

type Day struct {
	CommandExecutions    map[string]int `json:"command_executions"`
	ProxyCalls           int            `json:"proxy_calls"`
	ProxyBlocked         int            `json:"proxy_blocked"`
	ProxyRedacted        int            `json:"proxy_redacted"`
	SecretsResolved      int            `json:"secrets_resolved"`
	TotalProxyDurationMs int64          `json:"total_proxy_duration_ms"`
	InjectionStylesUsed  []string       `json:"injection_styles_used"`
	IntegrationsActive   []string       `json:"integrations_active"`

	// Snapshot metadata for the day
	CliVersion           string `json:"cli_version"`
	OS                   string `json:"os"`
	Arch                 string `json:"arch"`
	ActiveEnvironment    string `json:"active_environment"`
	UserEmail            string `json:"user_email,omitempty"`
	ProjectID            string `json:"project_id,omitempty"`
	WorkspaceID          string `json:"workspace_id,omitempty"`
	ProjectSecretCount   int    `json:"project_secret_count"`
	WorkspaceType        string `json:"workspace_type"`
	WorkspaceMemberCount int    `json:"workspace_member_count"`

	// Execution Path Breakdown
	ProxyCallsDaemon    int `json:"proxy_calls_daemon"`
	ProxyCallsTransient int `json:"proxy_calls_transient"`
	ProxyCallsMcp       int `json:"proxy_calls_mcp"`
	ProxyCallsDirect    int `json:"proxy_calls_direct"`
	DeveloperCommands   int `json:"developer_commands"`

	// Agentic Shielding
	SSRFAttemptsBlocked        int `json:"ssrf_attempts_blocked"`
	AllowlistViolations        int `json:"allowlist_violations"`
	ResponseRedactions         int `json:"response_redactions"`
	ProcessVerificationsFailed int `json:"process_verifications_failed"`
	ProductionWriteChallenges  int `json:"production_write_challenges"`

	// Latency & Performance
	KeychainResolutionMs int64 `json:"keychain_resolution_ms"`
	SessionRefreshMs     int64 `json:"session_refresh_ms"`

	// Onboarding & Friction
	InteractivePromptsShown   int `json:"interactive_prompts_shown"`
	InteractivePromptsSkipped int `json:"interactive_prompts_skipped"`
	DriftDiffsDetected        int `json:"drift_diffs_detected"`

	// Cryptographic Integrity
	LogChainVerifications int `json:"log_chain_verifications"`
	TamperingDetected     int `json:"tampering_detected"`

	// Node Metadata
	IsHeadlessNode      bool `json:"is_headless_node"`
	KeychainInitialized bool `json:"keychain_initialized"`

	// Typos
	Typos map[string]int `json:"typos"`

	// Agent Identity & Capabilities
	IdentityAnonymousCalls      int `json:"identity_anonymous_calls"`
	IdentityDeclaredCalls       int `json:"identity_declared_calls"`
	IdentityIssuedCalls         int `json:"identity_issued_calls"`
	CapabilityViolationsBlocked int `json:"capability_violations_blocked"`
	ProcessVerificationsPassed  int `json:"process_verifications_passed"`

	// Granular Error Categories
	ErrorsAuthCount     int `json:"errors_auth_count"`
	ErrorsKeychainCount int `json:"errors_keychain_count"`
	ErrorsSecretsCount  int `json:"errors_secrets_count"`
	ErrorsNetworkCount  int `json:"errors_network_count"`
	ErrorsSystemCount   int `json:"errors_system_count"`
	ErrorsUnknownCount  int `json:"errors_unknown_count"`
}

type Data struct {
	LastSync time.Time       `json:"last_sync"`
	Daily    map[string]*Day `json:"daily"`
}

// daySnapshot is the wire shape sent to telemetry.sync: every Day field
// (promoted from the embedded pointer, so its json tags are the source of
// truth) plus the bucket's date. Embedding keeps the payload in lockstep with
// Day — no field list to maintain in SyncIfDue.
type daySnapshot struct {
	*Day
	Date string `json:"date"`
}

var (
	mu    sync.Mutex
	data  *Data
	dirty bool
)

func telemetryFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".agentsecrets")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "telemetry.json"), nil
}

func loadLocked() error {
	if data != nil {
		return nil
	}

	path, err := telemetryFilePath()
	if err != nil {
		return err
	}

	data = &Data{
		Daily:    make(map[string]*Day),
		LastSync: time.Now(),
	}

	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return json.Unmarshal(b, data)
}

func saveLocked() error {
	if data == nil {
		return nil
	}
	path, err := telemetryFilePath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

// Flush persists any pending in-memory telemetry state to disk.
func Flush() error {
	mu.Lock()
	defer mu.Unlock()
	return flushLocked()
}

func flushLocked() error {
	if !dirty || data == nil {
		return nil
	}
	if err := saveLocked(); err != nil {
		return err
	}
	dirty = false
	return nil
}

func today() string {
	return time.Now().Format("2006-01-02")
}

func currentDayLocked() *Day {
	_ = loadLocked()
	if data.Daily == nil {
		data.Daily = make(map[string]*Day)
	}

	date := today()
	d, ok := data.Daily[date]
	if !ok {
		d = &Day{
			CommandExecutions:   make(map[string]int),
			InjectionStylesUsed: []string{},
			IntegrationsActive:  []string{},
			OS:                  runtime.GOOS,
			Arch:                runtime.GOARCH,
			Typos:               make(map[string]int),
		}
		data.Daily[date] = d
	}

	// Capture current context
	if LoadProjectIDFunc != nil {
		d.ProjectID = LoadProjectIDFunc()
	}
	if LoadGlobalConfigFunc != nil {
		wsID, email, wsType := LoadGlobalConfigFunc()
		d.WorkspaceID = wsID
		if email != "" {
			d.UserEmail = email
		}
		d.WorkspaceType = wsType
	}

	return d
}

// record is the single mutation primitive behind every Record* function. It
// mutates in-memory state instantly under a fast mutex lock and marks dirty,
// eliminating blocking disk I/O on hot execution paths.
func record(mutate func(d *Day)) {
	mu.Lock()
	defer mu.Unlock()
	mutate(currentDayLocked())
	dirty = true
}

// RecordCommand increments the usage count for a CLI command.
func RecordCommand(cmdName string) {
	record(func(d *Day) {
		if d.CommandExecutions == nil {
			d.CommandExecutions = make(map[string]int)
		}
		d.CommandExecutions[cmdName]++
		d.DeveloperCommands++
	})
}

// RecordProxyCall increments the total proxy call counter.
func RecordProxyCall() {
	record(func(d *Day) { d.ProxyCalls++ })
}

// RecordProxyBlocked increments the blocked proxy request counter.
func RecordProxyBlocked() {
	record(func(d *Day) { d.ProxyBlocked++ })
}

// RecordProxyRedacted increments the redacted proxy response counter.
func RecordProxyRedacted() {
	record(func(d *Day) {
		d.ProxyRedacted++
		d.ResponseRedactions++
	})
}

// RecordSecretResolved increments the resolved secrets count.
func RecordSecretResolved() {
	record(func(d *Day) { d.SecretsResolved++ })
}

// RecordProxyDuration adds proxy latency to the cumulative duration.
func RecordProxyDuration(ms int64) {
	record(func(d *Day) { d.TotalProxyDurationMs += ms })
}

// RecordInjectionStyle records a unique injection style used (e.g. "bearer", "header").
func RecordInjectionStyle(style string) {
	record(func(d *Day) {
		for _, s := range d.InjectionStylesUsed {
			if s == style {
				return
			}
		}
		d.InjectionStylesUsed = append(d.InjectionStylesUsed, style)
	})
}

// RecordIntegration records a unique integration (e.g. "mcp", "env", "proxy", "exec").
func RecordIntegration(name string) {
	record(func(d *Day) {
		for _, n := range d.IntegrationsActive {
			if n == name {
				return
			}
		}
		d.IntegrationsActive = append(d.IntegrationsActive, name)
	})
}

// RecordSecretCount records the current number of secrets in the project.
func RecordSecretCount(count int) {
	record(func(d *Day) { d.ProjectSecretCount = count })
}

// RecordWorkspaceMemberCount records the number of members in the workspace.
func RecordWorkspaceMemberCount(count int) {
	record(func(d *Day) { d.WorkspaceMemberCount = count })
}

// RecordProxyCallDaemon records a daemon proxy call.
func RecordProxyCallDaemon() {
	record(func(d *Day) { d.ProxyCallsDaemon++ })
}

// RecordProxyCallTransient records a transient proxy call.
func RecordProxyCallTransient() {
	record(func(d *Day) { d.ProxyCallsTransient++ })
}

// RecordProxyCallMcp records a proxy call from MCP.
func RecordProxyCallMcp() {
	record(func(d *Day) { d.ProxyCallsMcp++ })
}

// RecordProxyCallDirect records a direct proxy call.
func RecordProxyCallDirect() {
	record(func(d *Day) { d.ProxyCallsDirect++ })
}

// RecordSSRFAttemptsBlocked records a blocked SSRF attempt.
func RecordSSRFAttemptsBlocked() {
	record(func(d *Day) { d.SSRFAttemptsBlocked++ })
}

// RecordAllowlistViolation records an allowlist violation.
func RecordAllowlistViolation() {
	record(func(d *Day) { d.AllowlistViolations++ })
}

// RecordResponseRedaction records a response redaction event.
func RecordResponseRedaction() {
	record(func(d *Day) {
		d.ResponseRedactions++
		d.ProxyRedacted++
	})
}

// RecordProcessVerificationsFailed records a process verification failure.
func RecordProcessVerificationsFailed() {
	record(func(d *Day) { d.ProcessVerificationsFailed++ })
}

// RecordProductionWriteChallenge records a production write challenge.
func RecordProductionWriteChallenge() {
	record(func(d *Day) { d.ProductionWriteChallenges++ })
}

// RecordKeychainResolutionMs adds time to cumulative keychain resolution latency.
func RecordKeychainResolutionMs(ms int64) {
	record(func(d *Day) { d.KeychainResolutionMs += ms })
}

// RecordSessionRefreshMs adds time to cumulative session refresh latency.
func RecordSessionRefreshMs(ms int64) {
	record(func(d *Day) { d.SessionRefreshMs += ms })
}

// RecordInteractivePromptShown records showing an interactive prompt.
func RecordInteractivePromptShown() {
	record(func(d *Day) { d.InteractivePromptsShown++ })
}

// RecordInteractivePromptSkipped records skipping an interactive prompt.
func RecordInteractivePromptSkipped() {
	record(func(d *Day) { d.InteractivePromptsSkipped++ })
}

// RecordDriftDiffsDetected adds to detected drift diffs.
func RecordDriftDiffsDetected(count int) {
	record(func(d *Day) { d.DriftDiffsDetected += count })
}

// RecordLogChainVerification records a log chain verification.
func RecordLogChainVerification() {
	record(func(d *Day) { d.LogChainVerifications++ })
}

// RecordTamperingDetected records a tampering alert.
func RecordTamperingDetected() {
	record(func(d *Day) { d.TamperingDetected++ })
}

// RecordIdentityAnonymousCall records an anonymous identity proxy call.
func RecordIdentityAnonymousCall() {
	record(func(d *Day) { d.IdentityAnonymousCalls++ })
}

// RecordIdentityDeclaredCall records a declared identity proxy call.
func RecordIdentityDeclaredCall() {
	record(func(d *Day) { d.IdentityDeclaredCalls++ })
}

// RecordIdentityIssuedCall records an issued identity proxy call.
func RecordIdentityIssuedCall() {
	record(func(d *Day) { d.IdentityIssuedCalls++ })
}

// RecordCapabilityViolationBlocked records a capability violation block.
func RecordCapabilityViolationBlocked() {
	record(func(d *Day) { d.CapabilityViolationsBlocked++ })
}

// RecordProcessVerificationsPassed records a process verification pass.
func RecordProcessVerificationsPassed() {
	record(func(d *Day) { d.ProcessVerificationsPassed++ })
}

// RecordErrorAuth records an auth error.
func RecordErrorAuth() {
	record(func(d *Day) { d.ErrorsAuthCount++ })
}

// RecordErrorKeychain records a keychain error.
func RecordErrorKeychain() {
	record(func(d *Day) { d.ErrorsKeychainCount++ })
}

// RecordErrorSecrets records a secrets error.
func RecordErrorSecrets() {
	record(func(d *Day) { d.ErrorsSecretsCount++ })
}

// RecordErrorNetwork records a network error.
func RecordErrorNetwork() {
	record(func(d *Day) { d.ErrorsNetworkCount++ })
}

// RecordErrorSystem records a system error.
func RecordErrorSystem() {
	record(func(d *Day) { d.ErrorsSystemCount++ })
}

// RecordErrorUnknown records an unknown error.
func RecordErrorUnknown() {
	record(func(d *Day) { d.ErrorsUnknownCount++ })
}

// RecordTypo records a typo entry.
func RecordTypo(typo string) {
	record(func(d *Day) {
		if d.Typos == nil {
			d.Typos = make(map[string]int)
		}
		d.Typos[typo]++
	})
}

// SyncIfDue checks if 24 hours have passed and flushes telemetry to the cloud.
//
// The telemetry mutex is deliberately NOT held across the network call. The API
// call may need an access token, which forces a keychain read, which can cold-start
// the keychain connection — and initLocked records that through record(), which
// re-enters this package. Holding mu across the HTTP request would self-deadlock on
// that re-entrant record(). So: snapshot and mutate under mu, release it, do the
// I/O, then re-acquire to commit the result.
func SyncIfDue(client *api.Client, cliVersion string) {
	if client == nil {
		// Nothing to sync against — just persist whatever is dirty.
		mu.Lock()
		_ = flushLocked()
		mu.Unlock()
		return
	}

	// Snapshot and mutate under the lock, then release it for the network call.
	mu.Lock()
	snapshots, syncedDates, ok := prepareSyncLocked(cliVersion)
	mu.Unlock()

	if !ok {
		// Nothing due: persist whatever is dirty.
		mu.Lock()
		_ = flushLocked()
		mu.Unlock()
		return
	}

	// Use a short-timeout clone of the client for telemetry sync to prevent
	// broken DNS/network hangs. Cloning avoids mutating the shared client's
	// timeout, which would otherwise race with concurrent API calls.
	syncClient := client.Clone()
	syncClient.HTTPClient.Timeout = 1500 * time.Millisecond

	payload := map[string]interface{}{"snapshots": snapshots}

	// Network call outside the lock (see the note above about re-entrancy).
	err := syncClient.CallNoContent("telemetry.sync", "POST", payload, nil, nil)

	mu.Lock()
	defer mu.Unlock()
	if err != nil {
		_ = flushLocked()
		// Diagnostic noise must not pollute stdout, which commands like `doctor
		// --json` and `exec` reserve for machine-readable output.
		fmt.Fprintln(os.Stderr, "\n[DEBUG] Telemetry Sync Rejected by Backend:", err)
		return
	}

	// Success! Clear only the synced daily buckets. The current day is never in
	// syncedDates, so any telemetry recorded during the network call (e.g. by the
	// keychain init that the token read triggered) is preserved.
	for _, date := range syncedDates {
		delete(data.Daily, date)
	}
	data.LastSync = time.Now()
	_ = saveLocked()
	_ = flushLocked()
}

// prepareSyncLocked decides whether a sync is due and, if so, snapshots the daily
// buckets that should be sent. The caller must hold mu while calling it, but must
// release mu before the network call that follows. Returns ok=false when nothing
// needs syncing.
func prepareSyncLocked(cliVersion string) (snapshots []daySnapshot, syncedDates []string, ok bool) {
	_ = loadLocked()

	if time.Since(data.LastSync) < 24*time.Hour {
		return nil, nil, false
	}
	if len(data.Daily) == 0 {
		data.LastSync = time.Now()
		_ = saveLocked()
		return nil, nil, false
	}

	// Update metadata for today's bucket before syncing
	d := currentDayLocked()
	d.CliVersion = cliVersion
	if ResolveEnvironmentFunc != nil {
		d.ActiveEnvironment = ResolveEnvironmentFunc()
	} else {
		d.ActiveEnvironment = "development"
	}
	if KeychainInitializedFunc != nil {
		d.KeychainInitialized = KeychainInitializedFunc()
	}

	wsType := "personal"
	if LoadGlobalConfigFunc != nil {
		_, _, wType := LoadGlobalConfigFunc()
		if wType != "" {
			wsType = wType
		}
	}
	d.WorkspaceType = wsType
	// Keep the recorded WorkspaceMemberCount if set, otherwise default to 1.
	if d.WorkspaceMemberCount == 0 {
		d.WorkspaceMemberCount = 1
	}

	currentDate := today()
	for date, dayData := range data.Daily {
		if date == currentDate {
			// Don't send incomplete telemetry for the current day
			continue
		}
		snapshots = append(snapshots, daySnapshot{Day: dayData, Date: date})
		syncedDates = append(syncedDates, date)
	}

	if len(snapshots) == 0 {
		data.LastSync = time.Now()
		_ = saveLocked()
		return nil, nil, false
	}
	return snapshots, syncedDates, true
}
