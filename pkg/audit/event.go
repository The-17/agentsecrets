// Package audit defines the data types that describe a single proxied API call
// and its forensic record. These types are intentionally free of any behavior
// or dependencies on the proxy engine, so producers (the proxy) and consumers
// (the log service, MCP tools, CLI exporters) can share them without importing
// pkg/proxy.
package audit

import "time"

// AuditEvent records a single proxied API call.
// Secret KEY NAMES are logged. Secret VALUES are NEVER logged.
type AuditEvent struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	Environment    string    `json:"environment,omitempty"` // "development", "staging", "production"
	SecretKeys     []string  `json:"secret_keys"`           // KEY NAMES e.g. ["STRIPE_SECRET_KEY"]
	AgentID        string    `json:"agent_id,omitempty"`    // from agent identification
	IdentityLevel  string    `json:"identity_level"`        // "anonymous", "declared", "issued"
	Method         string    `json:"method"`
	TargetURL      string    `json:"target_url"`
	Domain         string    `json:"domain,omitempty"` // Target domain (e.g. "api.stripe.com")
	AuthStyles     []string  `json:"auth_styles"`      // e.g. ["bearer"]
	StatusCode     int       `json:"status_code"`
	DurationMs     int64     `json:"duration_ms"`
	Status         string    `json:"status"`           // "OK" or "BLOCKED"
	Reason         string    `json:"reason,omitempty"` // "domain_not_in_allowlist" or "-"
	Redacted       bool      `json:"redacted"`
	ResolutionPath string    `json:"resolution_path"`       // e.g. "local proxy", "cloud"
	CallerRole     string    `json:"caller_role,omitempty"` // e.g. "member"
	WorkspaceID    string    `json:"workspace_id,omitempty"`
	ProjectID      string    `json:"project_id,omitempty"`
	TokenID        string    `json:"token_id,omitempty"`

	// Attribution for `agentsecrets env`, which hands credentials to a child
	// process. The child's identity and the hosts its credentials name make an
	// incident provable; no secret value is ever recorded here.
	ChildBinary     string   `json:"child_binary,omitempty"`
	ChildHash       string   `json:"child_hash,omitempty"`
	ChildPID        int      `json:"child_pid,omitempty"`
	CredentialHosts []string `json:"credential_hosts,omitempty"`
}

type ForensicAuditEvent struct {
	ID          string           `json:"id"`
	Version     string           `json:"version"`
	CreatedAt   time.Time        `json:"created_at"`
	WorkspaceID string           `json:"workspace_id"`
	ProjectID   string           `json:"project_id"`
	Event       EventBlock       `json:"event"`
	Snapshot    SnapshotBlock    `json:"snapshot"`
	Enforcement EnforcementBlock `json:"enforcement"`
	Resolution  ResolutionBlock  `json:"resolution"`
	ChainHash   string           `json:"chain_hash"`
}

type EventBlock struct {
	Type          string         `json:"type"` // "proxy_call"
	KeyName       string         `json:"key_name"`
	Domain        string         `json:"domain"`
	Path          string         `json:"path"`
	Method        string         `json:"method"`
	StatusCode    int            `json:"status_code"`
	Outcome       string         `json:"outcome"`
	LatencyMs     int64          `json:"latency_ms"`
	AgentIdentity *AgentIdentity `json:"agent_identity,omitempty"`
	Environment   string         `json:"environment"`
	SecContractID string         `json:"sec_contract_id,omitempty"`
}

type AgentIdentity struct {
	TokenName       string `json:"token_name"`
	TokenID         string `json:"token_id"`
	IdentityLevel   string `json:"identity_level"`
	ProcessVerified bool   `json:"process_verified"`
}

type SnapshotBlock struct {
	CapturedAt        time.Time             `json:"captured_at"`
	Workspace         WorkspaceSnapshot     `json:"workspace"`
	Project           ProjectSnapshot       `json:"project"`
	SecretsInScope    []string              `json:"secrets_in_scope"`
	SecretsCount      int                   `json:"secrets_count"`
	AgentCapabilities *CapabilitiesSnapshot `json:"agent_capabilities,omitempty"`
	SecretsPolicy     *PolicySnapshot       `json:"secrets_policy,omitempty"`
	KeychainAuth      KeychainAuthSnapshot  `json:"keychain_auth"`
	Proxy             ProxySnapshot         `json:"proxy"`
}

type WorkspaceSnapshot struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Allowlist      []string `json:"allowlist"`
	AllowlistCount int      `json:"allowlist_count"`
}

type ProjectSnapshot struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Environment string `json:"environment"`
}

type CapabilitiesSnapshot struct {
	TokenName       string   `json:"token_name"`
	AllowedProjects []string `json:"allowed_projects"`
	AllowedSecrets  []string `json:"allowed_secrets"`
	Scopes          []string `json:"scopes"`
}

type PolicySnapshot struct {
	KeyName         string   `json:"key_name"`
	AllowedDomains  []string `json:"allowed_domains"`
	AllowedMethods  []string `json:"allowed_methods"`
	ViolationAction string   `json:"violation_action"`
	PolicyVersion   string   `json:"policy_version"`
}

type KeychainAuthSnapshot struct {
	Authenticated       bool `json:"authenticated"`
	ProcessHashVerified bool `json:"process_hash_verified"`
	SessionBound        bool `json:"session_bound"`
}

type ProxySnapshot struct {
	Version   string `json:"version"`
	Port      int    `json:"port"`
	Transient bool   `json:"transient"`
}

type EnforcementBlock struct {
	Decision          string            `json:"decision"` // "permitted" | "blocked" | ...
	DecidedBy         string            `json:"decided_by"`
	LayersEvaluated   []EvaluationLayer `json:"layers_evaluated"`
	FirstFailureLayer string            `json:"first_failure_layer,omitempty"`
}

type EvaluationLayer struct {
	Layer          string `json:"layer"`  // "agent_capabilities" | "workspace_allowlist" | "secrets_policy"
	Result         string `json:"result"` // "pass" | "fail"
	Reason         string `json:"reason"`
	ActionRequired string `json:"action_required,omitempty"`
}

type ResolutionBlock struct {
	CredentialInjected bool   `json:"credential_injected"`
	InjectionStyle     string `json:"injection_style,omitempty"`
	ResponseScanned    bool   `json:"response_scanned"`
	RedactionTriggered bool   `json:"redaction_triggered"`
	RedactionPattern   string `json:"redaction_pattern,omitempty"`
	RedactedField      string `json:"redacted_field,omitempty"`
	Replacement        string `json:"replacement,omitempty"`
	SSRFCheckPassed    bool   `json:"ssrf_check_passed"`
	ResponseStatus     int    `json:"response_status"`
}
