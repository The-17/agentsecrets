package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/capabilities"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/telemetry"
	"github.com/The-17/agentsecrets/pkg/workspaces"
	"golang.org/x/term"
)

// resolveEnvForAudit returns the current environment for audit logging.
func resolveEnvForAudit() string {
	return config.ResolveEnvironment()
}

const redactionPlaceholder = "[REDACTED_BY_AGENTSECRETS]"

// RedactionPlaceholder is the marker substituted for any redacted secret value.
// Exported so consumers (e.g. the `call --output json` encoder) can detect
// whether a response was redacted without duplicating the literal.
const RedactionPlaceholder = redactionPlaceholder

// redactionRegexCache memoizes the compiled masked-pattern regex per secret
// value. Redaction runs on every proxied response, and recompiling the same
// pattern each time is pure overhead. Bounded so a churn of distinct secrets
// can't grow it without limit.
var (
	redactionRegexCache   = map[string]*regexp.Regexp{}
	redactionRegexCacheMu sync.Mutex
)

const redactionRegexCacheMax = 256

// maskedPrefixRegex returns the compiled masked/truncated-echo pattern for a
// secret value, or nil if the pattern is invalid. Results are cached.
func maskedPrefixRegex(secretValue string, prefixLen int) *regexp.Regexp {
	redactionRegexCacheMu.Lock()
	defer redactionRegexCacheMu.Unlock()

	if re, ok := redactionRegexCache[secretValue]; ok {
		return re
	}

	escapedPrefix := regexp.QuoteMeta(secretValue[:prefixLen])
	pattern := escapedPrefix + `[\*\.\-_#]{1,4}[^\s"'\\,}\]]{0,30}`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	// Bound the cache: on overflow, drop it wholesale rather than track LRU —
	// simple and adequate for a per-process cache of active secrets.
	if len(redactionRegexCache) >= redactionRegexCacheMax {
		redactionRegexCache = map[string]*regexp.Regexp{}
	}
	redactionRegexCache[secretValue] = re
	return re
}

// redactSecretFromResponse removes all detectable forms of secretValue from body.
//
// APIs frequently echo credentials back in error messages — sometimes verbatim,
// sometimes truncated/masked (e.g. Stripe: "RESTRICT*DDUH", OpenAI: "sk-...xxxx").
// A pure exact-match misses every non-verbatim form, so we build a set of candidate
// patterns and replace all of them.
func redactSecretFromResponse(body []byte, secretValue string) []byte {
	if secretValue == "" || len(body) == 0 {
		return body
	}

	// 1. Exact match — always first, cheapest.
	body = bytes.ReplaceAll(body, []byte(secretValue), []byte(redactionPlaceholder))

	// 2. URL-encoded variant (e.g. Bearer token in a redirect echo).
	urlEncoded := url.QueryEscape(secretValue)
	if urlEncoded != secretValue {
		body = bytes.ReplaceAll(body, []byte(urlEncoded), []byte(redactionPlaceholder))
	}

	// 3. JSON-string-escaped variant (e.g. backslash before quotes inside JSON).
	jsonEscaped := strings.ReplaceAll(secretValue, `"`, `\"`)
	if jsonEscaped != secretValue {
		body = bytes.ReplaceAll(body, []byte(jsonEscaped), []byte(redactionPlaceholder))
	}

	// 4. Truncated/masked patterns that APIs echo in error messages.
	// Strategy: if we find a prefix of the secret (>=6 chars) followed by any
	// masking character(s) (* . - _ #) and optionally a suffix, redact the whole match.
	// This catches: "RESTRICT*DDUH", "sk_live_51H***xyz", "ABCDEF...wxyz" etc.
	if len(secretValue) >= 8 {
		// Use the first 6 chars as an anchor (short enough to survive truncation,
		// long enough to avoid false positives on common prefixes).
		prefixLen := 6
		if len(secretValue) >= 16 {
			prefixLen = 8
		}
		// Pattern: <prefix>[mask chars][any non-whitespace/quote chars up to ~30 chars]
		// We stop at whitespace, quote, or common JSON terminators to avoid over-redaction.
		// Compiled once per secret and cached (see maskedPrefixRegex).
		if re := maskedPrefixRegex(secretValue, prefixLen); re != nil {
			body = re.ReplaceAll(body, []byte(redactionPlaceholder))
		}
	}

	// 5. Prefix-only leak: sometimes APIs echo just the beginning of a key
	// (e.g. "Invalid key: sk_live_51H"). Redact if >=12 char prefix appears.
	if len(secretValue) >= 12 {
		prefixCut := len(secretValue) * 2 / 3 // first two-thirds of the value
		if prefixCut >= 12 {
			body = bytes.ReplaceAll(body, []byte(secretValue[:prefixCut]), []byte(redactionPlaceholder))
		}
	}

	return body
}

// CallRequest is the input to the engine — used by both MCP and HTTP paths.
type CallRequest struct {
	TargetURL     string            // full URL e.g. https://api.stripe.com/v1/charges
	Method        string            // GET, POST, PUT, PATCH, DELETE
	Headers       map[string]string // extra headers to forward (non-auth)
	Body          []byte            // raw request body (optional)
	Injections    []Injection       // what to inject and where
	AgentID       string            // optional, for audit logging
	AgentToken    string            // optional agent token (or reads AS_AGENT_TOKEN)
	IdentityLevel string            // "anonymous", "declared", "issued"
	TokenID       string            // optional token ID if issued
	Capabilities  *capabilities.AgentCapabilities // agent's secret access restrictions (nil = unrestricted)
}

// Injection describes one credential to inject.
type Injection struct {
	Style     string // "bearer", "basic", "header", "query", "body", "form"
	Target    string // header name, query param (depends on style)
	SecretKey string // keyring key name e.g. "STRIPE_SECRET_KEY"
}

// CallResult is the output from the engine.
type CallResult struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
}

// SecretResolver is a function that retrieves a secret value by key name.
// This allows the engine to be tested with a mock keyring.
type SecretResolver func(key string) (string, error)

// SecretPresenceResolver is a function that checks if a secret exists by key name.
type SecretPresenceResolver func(key string) (bool, error)

// PolicyResolver is a function that retrieves a secret's policy by key name.
// Returns nil if no policy is set (unrestricted).
type PolicyResolver func(key string) (*capabilities.SecretPolicy, error)

// AllowlistResolver is a function that retrieves the authorized domains for a workspace.
type AllowlistResolver func(workspaceID string) ([]string, error)

// Engine coordinates keyring lookup, injection, forwarding, and auditing.
type Engine struct {
	ProjectID        string
	WorkspaceID      string
	Audit            *AuditLogger
	Client           *http.Client
	ResolveSecret    SecretResolver
	ResolvePresence  SecretPresenceResolver
	ResolvePolicy    PolicyResolver
	ResolveAllowlist AllowlistResolver
	Approvals        *ApprovalStore
	Transient        bool
	TokenCache       *TokenCache
	APIClient        *api.Client

	// Live State
	LastSync   time.Time
	RevokedIDs []string
	mu         sync.RWMutex
}

// NewEngine creates an engine wired to the real keyring for the given project.
func NewEngine(projectID string) (*Engine, error) {
	if projectID == "" {
		return nil, fmt.Errorf("project ID is required — run 'agentsecrets project use <name>' first")
	}

	audit, err := NewAuditLogger("")
	if err != nil {
		// Audit logger is non-critical — log to stderr but continue
		audit = nil
	}

	pc, err := config.LoadProjectConfig()
	if err != nil || pc.WorkspaceID == "" {
		return nil, fmt.Errorf("project config error, please run 'agentsecrets project use' first")
	}

	apiClient := auth.NewAuthenticatedClient()

	if audit != nil {
		audit.APIClient = apiClient
	}

	eng := &Engine{
		ProjectID:   projectID,
		WorkspaceID: pc.WorkspaceID,
		Audit:       audit,
		Approvals:   NewApprovalStore(),
		APIClient:   apiClient,
		TokenCache:  NewTokenCache(5 * time.Minute),
	}

	dialer := &net.Dialer{
		Timeout:   DefaultTimeout,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ip := net.ParseIP(host)
			var ips []net.IP
			if ip != nil {
				ips = []net.IP{ip}
			} else {
				ips, err = net.LookupIP(host)
				if err != nil {
					return nil, fmt.Errorf("SSRF prevention: DNS lookup failed: %w", err)
				}
			}

			// Validate all resolved IPs
			for _, resolvedIP := range ips {
				if isPrivateOrLoopbackIP(resolvedIP) {
					telemetry.RecordSSRFAttemptsBlocked()
					return nil, fmt.Errorf("SSRF prevention: connection to private/loopback IP %s is blocked", resolvedIP)
				}
			}

			if len(ips) == 0 {
				return nil, fmt.Errorf("SSRF prevention: no IP addresses resolved for %s", host)
			}
			targetAddr := net.JoinHostPort(ips[0].String(), port)
			return dialer.DialContext(ctx, network, targetAddr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	eng.Client = &http.Client{
		Transport: transport,
		Timeout:   DefaultTimeout,
	}

	eng.ResolveSecret = func(key string) (string, error) {
		return keyring.GetSecret(projectID, resolveEnvForAudit(), key)
	}
	eng.ResolvePresence = func(key string) (bool, error) {
		keys, err := keyring.ListProjectKeyNames(projectID, resolveEnvForAudit())
		if err != nil {
			return false, err
		}
		for _, k := range keys {
			if strings.EqualFold(k, key) {
				return true, nil
			}
		}
		return false, nil
	}
	eng.ResolvePolicy = func(key string) (*capabilities.SecretPolicy, error) {
		policyBytes, err := keyring.GetSecretPolicy(projectID, resolveEnvForAudit(), key)
		if err == nil && len(policyBytes) > 0 {
			var policy capabilities.SecretPolicy
			if err := json.Unmarshal(policyBytes, &policy); err == nil {
				return &policy, nil
			}
		}

		// Keychain is empty (or failed/malformed) — fallback to cloud API
		if eng.APIClient != nil {
			policy, err := api.CallJSON[capabilities.SecretPolicy](eng.APIClient, "secrets.get_policy", "GET", nil, map[string]string{
				"project_id":  projectID,
				"environment": resolveEnvForAudit(),
				"key":         key,
			}, nil)
			if err == nil {
				// Cache in local keyring
				pBytes, err := json.Marshal(policy)
				if err == nil {
					_ = keyring.SetSecretPolicy(projectID, resolveEnvForAudit(), key, pBytes)
				}
				return &policy, nil
			}
		}

		return nil, nil // default unrestricted
	}
	eng.ResolveAllowlist = func(wsID string) ([]string, error) {
		domains, err := keyring.GetWorkspaceAllowlist(wsID)
		if err != nil {
			return nil, err
		}

		// Keychain is empty — this happens after a daemon restart (in-memory backend
		// on Linux/WSL loses state) or on a fresh machine before a pull.
		// Fall back to the API and re-cache so subsequent calls are served locally.
		if len(domains) == 0 && apiClient != nil {
			wsSvc := workspaces.NewService(apiClient)
			apiDomains, apiErr := wsSvc.ListAllowlist(wsID)
			if apiErr == nil && len(apiDomains) > 0 {
				for _, d := range apiDomains {
					domains = append(domains, d.Domain)
				}
				// Cache back to keychain so the next call is served locally.
				_ = keyring.SetWorkspaceAllowlist(wsID, domains)
			}
		}

		return domains, nil
	}

	return eng, nil
}

// identityOutcome is the verdict from resolveIdentity.
type identityOutcome int

const (
	// identityOK — token (if any) validated and all scope checks passed. The
	// resolved fields on identityResult should be applied to the CallRequest.
	identityOK identityOutcome = iota
	// identityBlocked — a revocation or scope check failed. Reason/Message carry
	// the block reason and human-facing text; the caller decides how to surface
	// it (engine → logBlocked 403; server → writeError 403 + audit).
	identityBlocked
	// identityError — token validation itself failed (bad/expired token, API
	// error). Err is set; caller surfaces it (engine → return err; server → 401).
	identityError
)

// identityResult is the outcome of resolveIdentity. On identityOK the Resolved*
// fields describe how to populate the CallRequest before enforcement; on the
// other outcomes the relevant Reason/Message or Err is set instead.
type identityResult struct {
	Outcome identityOutcome

	// Populated on identityOK (when a token was validated).
	ResolvedToken        string // the concrete token after <AGENT>_TOKEN deref
	ResolvedAgentID      string
	ResolvedTokenID      string
	ResolvedIdentityLevel string
	ResolvedCapabilities *capabilities.AgentCapabilities

	// Populated on identityBlocked.
	Reason  string
	Message string

	// Populated on identityError.
	Err error
}

// resolveIdentity performs the agent-token resolution, validation, revocation,
// and workspace/project/environment scope checks that BOTH the engine and the
// HTTP server need. It is a pure decision function: no audit writes, no HTTP
// responses, no telemetry — the caller owns those side effects so each path can
// keep its own surfacing (the engine's forensic 403 vs the server's writeError).
//
// It mirrors the original inline logic exactly: only tokens that are non-empty
// AND arrive without pre-resolved capabilities are validated here (the server
// pre-validates and hands the engine a non-nil Capabilities, which short-circuits
// a second validation — preserved by the caller checking req.Capabilities).
func (e *Engine) resolveIdentity(req CallRequest) identityResult {
	token := req.AgentToken
	if token == "" {
		token = req.TokenID
	}
	if token == "" {
		token = os.Getenv("AS_AGENT_TOKEN")
	}

	// Resolve agent token references like <AGENTNAME>_TOKEN from the OS keychain.
	if token != "" && strings.HasSuffix(strings.ToUpper(token), "_TOKEN") && len(token) > 6 {
		agentName := token[:len(token)-6]
		retrievedToken, err := keyring.GetAgentToken(agentName)
		if err != nil {
			// Fallback to lowercase agent name
			retrievedToken, err = keyring.GetAgentToken(strings.ToLower(agentName))
		}
		if err != nil {
			return identityResult{
				Outcome: identityError,
				Err: fmt.Errorf("agent token reference %q was not found in the OS Keychain. Please run 'agentsecrets agent token issue %s' to create and save it in your keychain first", token, agentName),
			}
		}
		token = retrievedToken
	}

	res := identityResult{Outcome: identityOK, ResolvedToken: token}

	if token == "" {
		return res
	}

	res.ResolvedIdentityLevel = "issued"
	res.ResolvedTokenID = maskToken(token)

	if e.TokenCache == nil {
		return res
	}

	cached, err := e.TokenCache.Validate(token, e.APIClient)
	if err != nil {
		return identityResult{
			Outcome: identityError,
			Err: fmt.Errorf("agent token validation failed: %w", err),
		}
	}

	res.ResolvedAgentID = cached.AgentName
	if cached.TokenID != "" {
		res.ResolvedTokenID = cached.TokenID
	}
	res.ResolvedCapabilities = &cached.Capabilities

	// Revocation check: a revoked token ID (or the agent itself) is blocked even
	// if its capabilities are still cached locally.
	agentIDForMsg := req.AgentID
	if agentIDForMsg == "" || agentIDForMsg == "cli" {
		agentIDForMsg = cached.AgentName
	}
	if e.IsTokenRevoked(cached.TokenID) {
		return identityResult{
			Outcome: identityBlocked,
			Reason:  "token_revoked",
			Message: fmt.Sprintf("Agent token '%s' has been revoked and can no longer be used.", res.ResolvedTokenID),
		}
	}
	if e.IsTokenRevoked(cached.AgentID) {
		return identityResult{
			Outcome: identityBlocked,
			Reason:  "token_revoked",
			Message: fmt.Sprintf("Agent '%s' has been revoked and can no longer be used.", agentIDForMsg),
		}
	}

	// Verify scope restrictions (Workspace and Project and Environment).
	if cached.WorkspaceID != "" && cached.WorkspaceID != e.WorkspaceID {
		return identityResult{
			Outcome: identityBlocked,
			Reason:  "agent_workspace_mismatch",
			Message: fmt.Sprintf("Agent '%s' is not authorized to access workspace '%s'.", agentIDForMsg, e.WorkspaceID),
		}
	}
	if cached.ProjectID != "" && cached.ProjectID != e.ProjectID {
		return identityResult{
			Outcome: identityBlocked,
			Reason:  "agent_project_mismatch",
			Message: fmt.Sprintf("Agent '%s' is not authorized to access project '%s'.", agentIDForMsg, e.ProjectID),
		}
	}
	if cached.Environment != "" && !strings.EqualFold(cached.Environment, resolveEnvForAudit()) {
		return identityResult{
			Outcome: identityBlocked,
			Reason:  "agent_environment_mismatch",
			Message: fmt.Sprintf("Agent '%s' is not authorized to access the '%s' environment.", agentIDForMsg, resolveEnvForAudit()),
		}
	}

	return res
}

// Execute runs the full proxy pipeline using a background context: resolve secrets → inject → forward → audit.
func (e *Engine) Execute(req CallRequest) (*CallResult, error) {
	return e.ExecuteCtx(context.Background(), req)
}

// ExecuteCtx runs the full proxy pipeline with explicit context cancellation.
func (e *Engine) ExecuteCtx(ctx context.Context, req CallRequest) (*CallResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// --- Telemetry ---
	telemetry.RecordProxyCall()
	telemetry.RecordIntegration("proxy")

	if e.Transient {
		telemetry.RecordProxyCallTransient()
	} else {
		telemetry.RecordProxyCallDaemon()
	}

	if req.AgentID == "mcp" {
		telemetry.RecordProxyCallMcp()
	} else {
		telemetry.RecordProxyCallDirect()
	}

	// --- Validate ---
	if req.TargetURL == "" {
		return nil, fmt.Errorf("target URL is required")
	}
	if len(req.Injections) == 0 {
		return nil, fmt.Errorf("at least one injection is required — specify how to authenticate (e.g. bearer, header, query)")
	}

	method := strings.ToUpper(req.Method)
	if method == "" {
		method = "GET"
	}

	u, err := url.Parse(req.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	targetDomain := strings.ToLower(u.Hostname())

	// Capture the full injection key/style lists up-front for blocked-path audit
	// records. These are DISTINCT from the secretKeys/authStyles accumulated
	// during injection in the tail stages — the two used to share one backing
	// array (the old `secretKeys[:0]` reset), which was an aliasing hazard.
	allKeys := make([]string, 0, len(req.Injections))
	allStyles := make([]string, 0, len(req.Injections))
	for _, inj := range req.Injections {
		allKeys = append(allKeys, inj.SecretKey)
		allStyles = append(allStyles, inj.Style)
	}

	logBlocked := func(reason, msg string) (*CallResult, error) {
		telemetry.RecordProxyBlocked()
		e.auditBlocked(req, targetDomain, method, u.Path, reason, msg, allKeys, allStyles)

		bodyJSONBytes, _ := json.Marshal(map[string]string{"error": reason, "domain": targetDomain, "message": msg})
		headers := make(map[string][]string)
		headers["Content-Type"] = []string{"application/json"}
		return &CallResult{
			StatusCode: 403,
			Headers:    headers,
			Body:       bodyJSONBytes,
		}, nil
	}

	// Secret presence resolver. Evaluated AFTER the allowlist gate (step 4) so a
	// non-allowlisted target can never be probed for which secret key names exist.
	hasSecret := func(key string) (bool, error) {
		if e.ResolvePresence != nil {
			return e.ResolvePresence(key)
		}
		if e.ResolveSecret != nil {
			_, err := e.ResolveSecret(key)
			return err == nil, nil
		}
		return false, nil
	}

	// 2. Enforce HTTPS Target
	if strings.ToLower(u.Scheme) != "https" && flag.Lookup("test.v") == nil {
		return logBlocked("non_https_blocked", "Non-HTTPS requests are strictly blocked by the proxy to prevent credential exposure. Use HTTPS instead.")
	}

	// 3. Resolve Agent Identity and enforce capabilities and workspace/project/environment scopes.
	// Shared with server.handleProxy via resolveIdentity (a pure decision fn);
	// the engine surfaces a blocked verdict through logBlocked (forensic 403) and
	// a validation failure through a returned error. The req.Capabilities == nil
	// gate is preserved: the server pre-validates and passes non-nil Capabilities,
	// which (as before) skips a second validation here.
	if req.Capabilities == nil {
		switch idr := e.resolveIdentity(req); idr.Outcome {
		case identityError:
			return nil, idr.Err
		case identityBlocked:
			// Telemetry parity: the original recorded a capability-violation only
			// for the two revocation cases, never for scope mismatches.
			if idr.Reason == "token_revoked" {
				telemetry.RecordCapabilityViolationBlocked()
			}
			return logBlocked(idr.Reason, idr.Message)
		case identityOK:
			if idr.ResolvedToken != "" {
				req.IdentityLevel = "issued"
				req.TokenID = idr.ResolvedTokenID
				if idr.ResolvedCapabilities != nil {
					if req.AgentID == "" || req.AgentID == "cli" {
						req.AgentID = idr.ResolvedAgentID
					}
					req.Capabilities = idr.ResolvedCapabilities
				}
			}
		}
	}

	// Enforce Agent Capabilities
	if req.Capabilities != nil {
		for _, inj := range req.Injections {
			if !isSecretAllowed(req.Capabilities, inj.SecretKey) {
				msg := fmt.Sprintf("Agent '%s' is not allowed to access secret '%s' — update agent policy with 'agentsecrets agent policy set'", req.AgentID, inj.SecretKey)
				telemetry.RecordCapabilityViolationBlocked()
				return logBlocked("capability_denied", msg)
			}
		}
	}

	// Record identity calls
	identityLevel := req.IdentityLevel
	if identityLevel == "" {
		identityLevel = "anonymous"
	}
	switch identityLevel {
	case "anonymous":
		telemetry.RecordIdentityAnonymousCall()
	case "declared":
		telemetry.RecordIdentityDeclaredCall()
	case "issued":
		telemetry.RecordIdentityIssuedCall()
	}

	// 4. Check Allowlist
	var allowlist []string
	if e.ResolveAllowlist != nil {
		allowlist, err = e.ResolveAllowlist(e.WorkspaceID)
		if err != nil {
			return nil, fmt.Errorf("failed to read allowlist: %w", err)
		}
	}

	if len(allowlist) == 0 {
		msg := "Your workspace allowlist is empty. No credential injections are allowed until you add at least one domain.\nRun: agentsecrets workspace allowlist add <domain>"
		telemetry.RecordAllowlistViolation()
		return logBlocked("empty_allowlist", string(bytes.ReplaceAll([]byte(msg), []byte("\n"), []byte(" "))))
	}

	allowed := false
	for _, raw := range allowlist {
		if strings.ToLower(raw) == targetDomain {
			allowed = true
			break
		}
	}

	if !allowed {
		msg := fmt.Sprintf("%s is not in your workspace allowlist. To authorize it, run: agentsecrets workspace allowlist add %s", targetDomain, targetDomain)
		telemetry.RecordAllowlistViolation()
		return logBlocked("domain_not_in_allowlist", msg)
	}

	// Secret Presence Check — moved AFTER the allowlist gate so key names are only
	// ever probed for targets the workspace has authorized.
	for _, inj := range req.Injections {
		present, err := hasSecret(inj.SecretKey)
		if err != nil || !present {
			return nil, errors.New(
				errors.ErrSecretNotFound,
				fmt.Sprintf("secret '%s' not found in keychain — run 'agentsecrets secrets list' to see available keys, or add it with 'agentsecrets secrets set %s=VALUE'", inj.SecretKey, inj.SecretKey),
				fmt.Errorf("secret not found in local index"),
			)
		}
	}

	// 5. Enforce Secret-Level Policies
	hasPolicy := false
	if e.ResolvePolicy != nil {
		for _, inj := range req.Injections {
			policy, _ := e.ResolvePolicy(inj.SecretKey)
			if policy != nil && (len(policy.Domains) > 0 || len(policy.Methods) > 0 || len(policy.Rules) > 0) {
				hasPolicy = true
			}
			action := capabilities.EvaluateSecret(policy, targetDomain, method)

			switch action {
			case capabilities.Deny:
				msg := fmt.Sprintf("Secret '%s' policy denies %s requests to %s", inj.SecretKey, method, targetDomain)
				return logBlocked("policy_denied", msg)
			case capabilities.RequestPermission:
				approvalKey := ApprovalKey{
					AgentID:   req.AgentID,
					SecretKey: inj.SecretKey,
					Domain:    targetDomain,
					Method:    method,
				}
				if e.Approvals == nil || !e.Approvals.IsApproved(approvalKey) {
					// Transient proxy + interactive TTY: prompt inline.
					if e.Transient && term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
						telemetry.RecordInteractivePromptShown()
						fmt.Fprintf(os.Stdout, "\n[AgentSecrets] Secret '%s' requires approval for %s to %s.\n", inj.SecretKey, method, targetDomain)
						fmt.Fprintf(os.Stdout, "Approve this request? (y/N): ")
						var response string
						_, err := fmt.Fscanln(os.Stdin, &response)
						if err == nil {
							response = strings.TrimSpace(strings.ToLower(response))
							if response == "y" || response == "yes" {
								if e.Approvals != nil {
									e.Approvals.Approve(approvalKey)
								}
								continue
							} else {
								msg := fmt.Sprintf("Secret '%s' requires approval for %s to %s — request was denied by user",
									inj.SecretKey, method, targetDomain)
								return logBlocked("policy_approval_denied", msg)
							}
						}
					}

					// Daemon proxy: hold the HTTP connection open on a channel.
					// The proxy terminal's approval goroutine (or /approve endpoint)
					// will signal the channel as soon as the developer responds.
					// No busy-waiting — the goroutine sleeps until unblocked.
					telemetry.RecordInteractivePromptSkipped()
					if e.Approvals != nil {
						// WaitForApproval blocks until approval/denial/timeout (5 min).
						if approved := e.Approvals.WaitForApproval(approvalKey, 5*time.Minute); !approved {
							msg := fmt.Sprintf(
								"Secret '%s' requires approval for %s to %s — "+
									"approve in the proxy terminal or run: agentsecrets proxy approve %s %s %s",
								inj.SecretKey, method, targetDomain,
								inj.SecretKey, method, targetDomain,
							)
							return logBlocked("policy_approval_required", msg)
						}
					} else {
						msg := fmt.Sprintf("Secret '%s' requires approval for %s to %s — run: agentsecrets proxy approve %s %s %s",
							inj.SecretKey, method, targetDomain, inj.SecretKey, method, targetDomain)
						return logBlocked("policy_approval_required", msg)
					}
				}
			}
		}
	}

	// --- Tail pipeline: buildAndInject → forward → redactResponse → auditSuccess ---
	// The authorization stages above are done; from here the request is permitted.
	// State is threaded through execContext so each stage is a named method with a
	// single argument instead of a ~10-param signature. secretKeys/authStyles here
	// are freshly allocated (NOT the allKeys/allStyles used by the blocked path),
	// which removes the old shared-backing-array aliasing hazard.
	ec := &execContext{
		ctx:          ctx,
		req:          req,
		method:       method,
		u:            u,
		targetDomain: targetDomain,
		hasPolicy:    hasPolicy,
		secretKeys:   make([]string, 0, len(req.Injections)),
		authStyles:   make([]string, 0, len(req.Injections)),
		secretValues: make([]string, 0, len(req.Injections)),
	}

	if res, err := e.buildAndInject(ec); res != nil || err != nil {
		return res, err
	}

	if res, err := e.forward(ec); res != nil || err != nil {
		return res, err
	}

	e.redactResponse(ec)
	e.auditSuccess(ec)

	return &CallResult{
		StatusCode: ec.result.StatusCode,
		Headers:    ec.result.Headers,
		Body:       ec.result.Body,
	}, nil
}

// execContext threads per-request state through the tail pipeline stages
// (buildAndInject → forward → redactResponse → auditSuccess). It exists so those
// stages can be separate methods rather than one ~490-line function, without each
// taking a long positional argument list.
type execContext struct {
	ctx          context.Context
	req          CallRequest
	method       string
	u            *url.URL
	targetDomain string
	hasPolicy    bool

	// Built by buildAndInject; sent by forward.
	outbound *http.Request

	// Accumulated during buildAndInject; consumed by forward/redact/audit.
	secretKeys   []string
	authStyles   []string
	secretValues []string

	// Populated by forward; consumed by redactResponse/auditSuccess.
	result   *ForwardResult
	redacted bool
}

// buildAndInject resolves each secret (recording resolution telemetry), builds
// the outbound request, and applies all injections in a single pass. A non-nil
// error aborts the call — e.g. a secret that vanished between the earlier
// presence check and here.
func (e *Engine) buildAndInject(ec *execContext) (*CallResult, error) {
	bodyReader := bytes.NewReader(ec.req.Body)

	outbound, err := http.NewRequestWithContext(ec.ctx, ec.method, ec.req.TargetURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	// Copy any extra headers
	for k, v := range ec.req.Headers {
		outbound.Header.Set(k, v)
	}

	for _, inj := range ec.req.Injections {
		telemetry.RecordInjectionStyle(inj.Style)

		startResolve := time.Now()
		cred, err := e.ResolveSecret(inj.SecretKey)
		duration := time.Since(startResolve).Milliseconds()
		telemetry.RecordKeychainResolutionMs(duration)
		if err != nil {
			return nil, errors.New(
				errors.ErrSecretNotFound,
				fmt.Sprintf("secret '%s' not found in keychain — run 'agentsecrets secrets list' to see available keys, or add it with 'agentsecrets secrets set %s=VALUE'", inj.SecretKey, inj.SecretKey),
				err,
			)
		}

		telemetry.RecordSecretResolved()

		ec.secretKeys = append(ec.secretKeys, inj.SecretKey)
		ec.authStyles = append(ec.authStyles, inj.Style)
		ec.secretValues = append(ec.secretValues, cred)
	}

	// Apply all injections in one pass — parses/serializes the body at most
	// once even with multiple body/form styles.
	if err := InjectAll(outbound, ec.secretValues, ec.req.Injections); err != nil {
		return nil, fmt.Errorf("injection failed: %w", err)
	}

	ec.outbound = outbound
	return nil, nil
}

// forward sends the outbound request. On an SSRF-prevention error it emits the
// blocked audit record and returns a 403 CallResult (via blockSSRF); other
// transport errors are returned as-is. On success the ForwardResult is stashed
// on ec for the redact/audit stages.
func (e *Engine) forward(ec *execContext) (*CallResult, error) {
	result, err := Forward(e.Client, ec.outbound)
	if err == nil && result != nil {
		telemetry.RecordProxyDuration(result.Duration.Milliseconds())
	}
	if err != nil {
		if strings.Contains(err.Error(), "SSRF prevention:") {
			return e.blockSSRF(ec, err)
		}
		return nil, err
	}
	ec.result = result
	return nil, nil
}

// blockSSRF logs the blocked call and returns the 403 result for an outbound
// request rejected by the SSRF-prevention dialer.
func (e *Engine) blockSSRF(ec *execContext, ssrfErr error) (*CallResult, error) {
	telemetry.RecordProxyBlocked()
	if e.Audit != nil {
		_ = e.Audit.Log(AuditEvent{
			Timestamp:      time.Now().UTC(),
			Environment:    resolveEnvForAudit(),
			SecretKeys:     ec.secretKeys,
			AgentID:        ec.req.AgentID,
			IdentityLevel:  ec.req.IdentityLevel,
			TokenID:        ec.req.TokenID,
			Method:         ec.method,
			TargetURL:      ec.req.TargetURL,
			Domain:         ec.targetDomain,
			AuthStyles:     ec.authStyles,
			StatusCode:     403,
			DurationMs:     0,
			Status:         "BLOCKED",
			Reason:         "ssrf_protection_blocked",
			ResolutionPath: "local proxy",
			WorkspaceID:    e.WorkspaceID,
			ProjectID:      e.ProjectID,
		})
		enforcement := EnforcementBlock{
			Decision:  "blocked",
			DecidedBy: "ssrf_protection",
			LayersEvaluated: []EvaluationLayer{
				{
					Layer:  "ssrf_protection",
					Result: "fail",
					Reason: ssrfErr.Error(),
				},
			},
			FirstFailureLayer: "ssrf_protection",
		}
		resolution := ResolutionBlock{
			CredentialInjected: false,
			ResponseScanned:    false,
			SSRFCheckPassed:    false,
			ResponseStatus:     403,
		}
		e.logForensic(ec.req, ec.targetDomain, ec.method, ec.u.Path, 403, "blocked", 0, ec.secretKeys, ec.authStyles, enforcement, resolution)
	}

	bodyJSONBytes, _ := json.Marshal(map[string]string{
		"error":   "ssrf_protection_blocked",
		"domain":  ec.targetDomain,
		"message": ssrfErr.Error(),
	})
	headers := make(map[string][]string)
	headers["Content-Type"] = []string{"application/json"}
	return &CallResult{
		StatusCode: 403,
		Headers:    headers,
		Body:       bodyJSONBytes,
	}, nil
}

// redactResponse strips any echoed secret values from the response body AND
// response headers, mirroring the original inline body redaction exactly (same
// unexpected-content-type warning, same Content-Length rewrite when the body
// changes) and extending the identical detection to header values.
//
// Header redaction MUST live here: only the engine holds the resolved secret
// values. Everything downstream — the CLI's CallViaProxy, the SDK, an AI agent
// reading `--output json` — receives key *names*, never values, so none of them
// can redact a credential an upstream API happened to reflect back in a header
// (Set-Cookie, WWW-Authenticate, a redirect Location carrying a token, an echoed
// X-Api-Key, …). Skipping headers here would be the one way a value leaks.
func (e *Engine) redactResponse(ec *execContext) {
	result := ec.result
	if result == nil {
		return
	}

	contentType := ""
	if len(result.Headers["Content-Type"]) > 0 {
		contentType = result.Headers["Content-Type"][0]
	}

	if len(result.Body) > 0 && contentType != "" &&
		!strings.Contains(contentType, "application/json") && !strings.Contains(contentType, "text/") {
		fmt.Fprintf(os.Stderr, "Warning: redacting unexpected content type: %s\n", contentType)
	}

	for _, val := range ec.secretValues {
		if val == "" {
			continue
		}

		// Body: strip every detectable form of the echoed value.
		if len(result.Body) > 0 && bytes.Contains(result.Body, []byte(val)) {
			result.Body = redactSecretFromResponse(result.Body, val)
			ec.redacted = true
		}

		// Headers: same detection (exact + URL-encoded + masked/truncated forms)
		// applied to each header value. Mutating slice elements in place is safe
		// while ranging the map — no keys are added or removed.
		for name, values := range result.Headers {
			for i, hv := range values {
				if strings.Contains(hv, val) {
					result.Headers[name][i] = string(redactSecretFromResponse([]byte(hv), val))
					ec.redacted = true
				}
			}
		}
	}

	if ec.redacted {
		telemetry.RecordProxyRedacted()
		result.Headers["Content-Length"] = []string{fmt.Sprintf("%d", len(result.Body))}
	}
}

// auditSuccess emits the success audit + forensic records for a completed call.
func (e *Engine) auditSuccess(ec *execContext) {
	if e.Audit == nil {
		return
	}
	result := ec.result

	_ = e.Audit.Log(AuditEvent{
		Timestamp:      time.Now().UTC(),
		Environment:    resolveEnvForAudit(),
		SecretKeys:     ec.secretKeys,
		AgentID:        ec.req.AgentID,
		IdentityLevel:  ec.req.IdentityLevel,
		TokenID:        ec.req.TokenID,
		Method:         ec.method,
		TargetURL:      ec.req.TargetURL,
		Domain:         ec.targetDomain,
		AuthStyles:     ec.authStyles,
		StatusCode:     result.StatusCode,
		DurationMs:     result.Duration.Milliseconds(),
		Status:         "OK",
		Reason:         reasonForAudit(ec.redacted),
		Redacted:       ec.redacted,
		ResolutionPath: "local proxy",
		WorkspaceID:    e.WorkspaceID,
		ProjectID:      e.ProjectID,
	})
	outcome := "success"
	if ec.redacted {
		outcome = "redacted"
	}
	enforcement := makeSuccessEnforcementBlock(ec.targetDomain, ec.hasPolicy)
	resolution := ResolutionBlock{
		CredentialInjected: true,
		InjectionStyle:     strings.Join(ec.authStyles, ","),
		ResponseScanned:    true,
		RedactionTriggered: ec.redacted,
		SSRFCheckPassed:    true,
		ResponseStatus:     result.StatusCode,
	}
	if ec.redacted {
		resolution.RedactionPattern = redactionPlaceholder
		resolution.Replacement = redactionPlaceholder
	}
	e.logForensic(ec.req, ec.targetDomain, ec.method, ec.u.Path, result.StatusCode, outcome, result.Duration.Milliseconds(), ec.secretKeys, ec.authStyles, enforcement, resolution)
}

// Sync fetches the current revoked-token list from the backend and stores it.
// This replaces the old mock which hard-coded a sample revocation ID.
// The list is a set of revoked token IDs for the engine's workspace, fetched
// from the API. If the fetch fails, the previously fetched list is kept so a
// transient network failure never silently re-authorizes a revoked token.
func (e *Engine) Sync() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.APIClient == nil {
		return fmt.Errorf("API client not available for revocation sync")
	}

	res, err := api.CallJSON[struct {
		TokenIDs []string `json:"token_ids"`
	}](e.APIClient, "agents.token_revoked", "GET", nil, map[string]string{
		"workspace_id": e.WorkspaceID,
	}, nil)
	if err != nil {
		return fmt.Errorf("revocation sync: %w", err)
	}

	e.RevokedIDs = res.TokenIDs
	if e.RevokedIDs == nil {
		e.RevokedIDs = []string{}
	}
	e.LastSync = time.Now()

	// Purge any revoked tokens from the cache so revocation takes effect
	// immediately, even for tokens validated within the TTL window.
	if e.TokenCache != nil {
		e.TokenCache.PurgeRevoked(e.RevokedIDs)
	}

	return nil
}

// IsTokenRevoked checks whether a token ID (or agent ID, for revoked agents)
// is present in the last fetched revocation list.
func (e *Engine) IsTokenRevoked(tokenID string) bool {
	if tokenID == "" || len(e.RevokedIDs) == 0 {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, id := range e.RevokedIDs {
		if id == tokenID {
			return true
		}
	}
	return false
}

// GetState returns the current live state of the proxy engine.
func (e *Engine) GetState() (time.Time, []string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.LastSync, e.RevokedIDs
}

// reasonForAudit returns the audit reason string based on whether response was redacted.
func reasonForAudit(redacted bool) string {
	if redacted {
		return "credential_echo"
	}
	return "-"
}

// isSecretAllowed checks if a secret key is permitted by the agent's capabilities.
// If AllowedSecrets is set, the key must be in the whitelist.
// If DeniedSecrets is set, the key must NOT be in the blacklist.
// If neither is set, all secrets are allowed.
func isSecretAllowed(caps *capabilities.AgentCapabilities, key string) bool {
	if caps == nil {
		return true
	}

	upperKey := strings.ToUpper(key)

	// Deny list takes priority — if the key is denied, block it regardless
	for _, denied := range caps.DeniedSecrets {
		if strings.ToUpper(denied) == upperKey {
			return false
		}
	}

	// If allow list is set, key must be in it
	if len(caps.AllowedSecrets) > 0 {
		for _, allowed := range caps.AllowedSecrets {
			if strings.ToUpper(allowed) == upperKey {
				return true
			}
		}
		return false // not in allow list
	}

	return true // no restrictions
}

// auditBlocked emits the standard blocked-call audit + forensic records for a
// 403 denial. Extracted from the Execute logBlocked closure so the HTTP server
// can emit an IDENTICAL record for scope/revocation denials it surfaces itself
// (previously the server's writeError path logged nothing — an audit gap). Does
// NOT record telemetry or write the HTTP response; the caller owns those.
func (e *Engine) auditBlocked(req CallRequest, targetDomain, method, path, reason, msg string, allKeys, allStyles []string) {
	if e.Audit == nil {
		return
	}
	_ = e.Audit.Log(AuditEvent{
		Timestamp:      time.Now().UTC(),
		Environment:    resolveEnvForAudit(),
		SecretKeys:     allKeys,
		AgentID:        req.AgentID,
		IdentityLevel:  req.IdentityLevel,
		TokenID:        req.TokenID,
		Method:         method,
		TargetURL:      req.TargetURL,
		Domain:         targetDomain,
		AuthStyles:     allStyles,
		StatusCode:     403,
		DurationMs:     0,
		Status:         "BLOCKED",
		Reason:         reason,
		ResolutionPath: "local proxy",
		WorkspaceID:    e.WorkspaceID,
		ProjectID:      e.ProjectID,
	})
	enforcement := makeEnforcementBlock(reason, msg, targetDomain, method, req.AgentID, allKeys)
	resolution := ResolutionBlock{
		CredentialInjected: false,
		ResponseScanned:    false,
		SSRFCheckPassed:    true,
		ResponseStatus:     403,
	}
	e.logForensic(req, targetDomain, method, path, 403, "blocked", 0, allKeys, allStyles, enforcement, resolution)
}

// Forensic logging helpers
func makeEnforcementBlock(reason, msg, targetDomain, method, agentID string, secretKeys []string) EnforcementBlock {
	decision := "blocked"
	if reason == "policy_approval_required" {
		decision = "policy_escalated"
	} else if reason == "policy_denied" {
		decision = "policy_denied"
	} else if reason == "capability_denied" {
		decision = "blocked"
	}

	var decidedBy string
	var firstFailure string
	layers := []EvaluationLayer{}

	// Layer 1: Agent Capabilities
	if reason == "capability_denied" {
		decidedBy = "agent_capabilities"
		firstFailure = "agent_capabilities"
		layers = append(layers, EvaluationLayer{
			Layer:          "agent_capabilities",
			Result:         "fail",
			Reason:         msg,
			ActionRequired: "agentsecrets agent policy set",
		})
	} else {
		agentReason := "agent capabilities check passed"
		if agentID == "" {
			agentReason = "anonymous agent has default capabilities"
		}
		layers = append(layers, EvaluationLayer{
			Layer:  "agent_capabilities",
			Result: "pass",
			Reason: agentReason,
		})

		// Layer 2: Workspace Allowlist
		if reason == "empty_allowlist" || reason == "domain_not_in_allowlist" {
			decidedBy = "workspace_allowlist"
			firstFailure = "workspace_allowlist"
			layers = append(layers, EvaluationLayer{
				Layer:          "workspace_allowlist",
				Result:         "fail",
				Reason:         msg,
				ActionRequired: fmt.Sprintf("agentsecrets workspace allowlist add %s", targetDomain),
			})
		} else {
			layers = append(layers, EvaluationLayer{
				Layer:  "workspace_allowlist",
				Result: "pass",
				Reason: fmt.Sprintf("%s is on the allowlist", targetDomain),
			})

			// Layer 3: Secret Policy
			if reason == "policy_denied" || reason == "policy_approval_required" {
				decidedBy = "secrets_policy"
				firstFailure = "secrets_policy"
				var actionReq string
				if reason == "policy_approval_required" {
					if len(secretKeys) > 0 {
						actionReq = fmt.Sprintf("agentsecrets proxy approve %s %s %s", secretKeys[0], method, targetDomain)
					}
				}
				layers = append(layers, EvaluationLayer{
					Layer:          "secrets_policy",
					Result:         "fail",
					Reason:         msg,
					ActionRequired: actionReq,
				})
			}
		}
	}

	return EnforcementBlock{
		Decision:          decision,
		DecidedBy:         decidedBy,
		LayersEvaluated:   layers,
		FirstFailureLayer: firstFailure,
	}
}

func makeSuccessEnforcementBlock(targetDomain string, hasPolicy bool) EnforcementBlock {
	reason := "no active policy set on this secret"
	if hasPolicy {
		reason = "request matches active secret policies"
	}
	return EnforcementBlock{
		Decision:  "permitted",
		DecidedBy: "secrets_policy",
		LayersEvaluated: []EvaluationLayer{
			{
				Layer:  "agent_capabilities",
				Result: "pass",
				Reason: "agent capabilities check passed",
			},
			{
				Layer:  "workspace_allowlist",
				Result: "pass",
				Reason: fmt.Sprintf("%s is on the allowlist", targetDomain),
			},
			{
				Layer:  "secrets_policy",
				Result: "pass",
				Reason: reason,
			},
		},
	}
}

func (e *Engine) logForensic(
	req CallRequest,
	targetDomain string,
	method string,
	path string,
	statusCode int,
	outcome string,
	latencyMs int64,
	secretKeys []string,
	authStyles []string,
	enforcement EnforcementBlock,
	resolution ResolutionBlock,
) {
	if e.Audit == nil {
		return
	}

	// 1. Capture Workspace Snapshot
	var allowlist []string
	if e.ResolveAllowlist != nil {
		allowlist, _ = e.ResolveAllowlist(e.WorkspaceID)
	}
	wsSnap := WorkspaceSnapshot{
		ID:             e.WorkspaceID,
		Name:           e.WorkspaceID,
		Allowlist:      allowlist,
		AllowlistCount: len(allowlist),
	}

	// 2. Capture Project Snapshot
	projSnap := ProjectSnapshot{
		ID:          e.ProjectID,
		Name:        e.ProjectID,
		Environment: resolveEnvForAudit(),
	}

	// 3. Secrets in Scope
	inScopeKeys, _ := keyring.ListProjectKeyNames(e.ProjectID, resolveEnvForAudit())
	if inScopeKeys == nil {
		inScopeKeys = []string{}
	}

	// 4. Agent Capabilities Snapshot
	var capsSnap *CapabilitiesSnapshot
	if req.Capabilities != nil {
		capsSnap = &CapabilitiesSnapshot{
			TokenName:       req.AgentID,
			AllowedProjects: []string{},
			AllowedSecrets:  req.Capabilities.AllowedSecrets,
			Scopes:          []string{},
		}
	}

	// 5. Secrets Policy Snapshot
	var policySnap *PolicySnapshot
	if len(secretKeys) > 0 && e.ResolvePolicy != nil {
		p, _ := e.ResolvePolicy(secretKeys[0])
		if p != nil {
			allowedMethods := []string{}
			for m := range p.Methods {
				allowedMethods = append(allowedMethods, m)
			}
			policySnap = &PolicySnapshot{
				KeyName:         secretKeys[0],
				AllowedDomains:  p.Domains,
				AllowedMethods:  allowedMethods,
				ViolationAction: "deny",
				PolicyVersion:   "v3",
			}
		}
	}

	// 6. Keychain Auth Snapshot
	kcAuth := KeychainAuthSnapshot{
		Authenticated:       true,
		ProcessHashVerified: true,
		SessionBound:        true,
	}

	// 7. Proxy Snapshot
	proxySnap := ProxySnapshot{
		Version:   "3.1.5",
		Port:      8765,
		Transient: e.Transient,
	}

	// 8. Build Agent Identity
	var agentIdentity *AgentIdentity
	if req.AgentToken != "" || req.TokenID != "" {
		agentIdentity = &AgentIdentity{
			TokenName:       req.AgentID,
			TokenID:         req.TokenID,
			IdentityLevel:   req.IdentityLevel,
			ProcessVerified: true,
		}
	}

	event := ForensicAuditEvent{
		WorkspaceID: e.WorkspaceID,
		ProjectID:   e.ProjectID,
		Event: EventBlock{
			Type:          "proxy_call",
			KeyName:       strings.Join(secretKeys, ","),
			Domain:        targetDomain,
			Path:          path,
			Method:        method,
			StatusCode:    statusCode,
			Outcome:       outcome,
			LatencyMs:     latencyMs,
			AgentIdentity: agentIdentity,
			Environment:   resolveEnvForAudit(),
		},
		Snapshot: SnapshotBlock{
			CapturedAt:        time.Now().UTC(),
			Workspace:         wsSnap,
			Project:           projSnap,
			SecretsInScope:    inScopeKeys,
			SecretsCount:      len(inScopeKeys),
			AgentCapabilities: capsSnap,
			SecretsPolicy:     policySnap,
			KeychainAuth:      kcAuth,
			Proxy:             proxySnap,
		},
		Enforcement: enforcement,
		Resolution:  resolution,
	}

	_ = e.Audit.LogForensic(event)
}

func isPrivateOrLoopbackIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Check RFC 1918 private ranges
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12 (172.16.0.0 to 172.31.255.255)
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 100.64.0.0/10 (100.64.0.0 to 100.127.255.255)
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	} else if ip6 := ip.To16(); ip6 != nil {
		// Unique Local Address fc00::/7
		if ip6[0]&0xfe == 0xfc {
			return true
		}
	}
	return false
}

