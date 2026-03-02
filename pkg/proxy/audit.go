package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEvent records a single proxied API call.
// Secret KEY NAMES are logged. Secret VALUES are NEVER logged.
type AuditEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	SecretKeys []string  `json:"secret_keys"`           // KEY NAMES e.g. ["STRIPE_SECRET_KEY"]
	AgentID    string    `json:"agent_id,omitempty"`     // from agent identification
	Method     string    `json:"method"`
	TargetURL  string    `json:"target_url"`
	Domain     string    `json:"domain,omitempty"`       // Target domain (e.g. "api.stripe.com")
	AuthStyles []string  `json:"auth_styles"`            // e.g. ["bearer"]
	StatusCode int       `json:"status_code"`
	DurationMs int64     `json:"duration_ms"`
	Status     string    `json:"status"`                 // "OK" or "BLOCKED"
	Reason     string    `json:"reason,omitempty"`       // "domain_not_in_allowlist" or "-"
}

// AuditLogger writes AuditEvents as JSONL to an append-only log file.
type AuditLogger struct {
	file *os.File
	mu   sync.Mutex
}

// DefaultLogPath returns the default audit log path: ~/.agentsecrets/proxy.log
func DefaultLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".agentsecrets")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("cannot create config directory: %w", err)
	}
	return filepath.Join(dir, "proxy.log"), nil
}

// NewAuditLogger creates an audit logger that appends to the given file path.
// If logPath is empty, the default path (~/.agentsecrets/proxy.log) is used.
func NewAuditLogger(logPath string) (*AuditLogger, error) {
	if logPath == "" {
		var err error
		logPath, err = DefaultLogPath()
		if err != nil {
			return nil, err
		}
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open audit log: %w", err)
	}

	return &AuditLogger{file: f}, nil
}

// Log writes a single audit event as a JSON line.
func (a *AuditLogger) Log(event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}

	data = append(data, '\n')
	_, err = a.file.Write(data)
	return err
}

// Close closes the underlying log file.
func (a *AuditLogger) Close() error {
	if a.file != nil {
		return a.file.Close()
	}
	return nil
}
