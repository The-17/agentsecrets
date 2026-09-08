package proxy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/audit"
	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/config"
	_ "github.com/glebarez/go-sqlite"
	"github.com/google/uuid"
)

// The audit event data types now live in pkg/audit so that consumers (pkg/log,
// pkg/mcp, CLI exporters) can share them without importing pkg/proxy. These
// aliases keep every existing proxy.AuditEvent / proxy.ForensicAuditEvent (etc.)
// reference valid with zero churn — they are the SAME types, not copies.
type (
	AuditEvent           = audit.AuditEvent
	ForensicAuditEvent   = audit.ForensicAuditEvent
	EventBlock           = audit.EventBlock
	AgentIdentity        = audit.AgentIdentity
	SnapshotBlock        = audit.SnapshotBlock
	WorkspaceSnapshot    = audit.WorkspaceSnapshot
	ProjectSnapshot      = audit.ProjectSnapshot
	CapabilitiesSnapshot = audit.CapabilitiesSnapshot
	PolicySnapshot       = audit.PolicySnapshot
	KeychainAuthSnapshot = audit.KeychainAuthSnapshot
	ProxySnapshot        = audit.ProxySnapshot
	EnforcementBlock     = audit.EnforcementBlock
	EvaluationLayer      = audit.EvaluationLayer
	ResolutionBlock      = audit.ResolutionBlock
)

// AuditLogger writes AuditEvents to a local SQLite database and syncs them to the cloud.
//
// Writes are performed asynchronously by a single background goroutine draining
// writeCh. Using one writer preserves both insertion order and the forensic
// hash-chain (each LogForensic reads the previous row's ID before inserting),
// while keeping the two SQLite writes + the chain-hash SELECT off the proxy's
// request-handling path. Close() drains outstanding writes; SyncUnpushedLogs()
// flushes before reading so it always sees a consistent view.
type AuditLogger struct {
	db        *sql.DB
	APIClient *api.Client
	mu        sync.Mutex // serializes the background writer against SyncUnpushedLogs

	writeCh   chan func()
	wg        sync.WaitGroup
	closeOnce sync.Once
	closed    chan struct{}
}

// auditWriteBuffer bounds the number of queued audit writes. Kept small so an
// abrupt process exit can only lose a handful of not-yet-flushed events; a full
// buffer falls back to a synchronous write rather than dropping the event.
const auditWriteBuffer = 256

// startWriter launches the single background write goroutine. It drains
// writeCh until closed is signalled AND the queue is empty, so events enqueued
// right before Close still land.
func (a *AuditLogger) startWriter() {
	a.writeCh = make(chan func(), auditWriteBuffer)
	a.closed = make(chan struct{})
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		for {
			select {
			case fn := <-a.writeCh:
				fn()
			case <-a.closed:
				// Drain whatever is still queued, then exit.
				for {
					select {
					case fn := <-a.writeCh:
						fn()
					default:
						return
					}
				}
			}
		}
	}()
}

// enqueue schedules fn on the background writer. If the buffer is full or the
// logger is closing, fn runs synchronously so an audit event is never dropped.
func (a *AuditLogger) enqueue(fn func()) {
	select {
	case <-a.closed:
		fn()
		return
	default:
	}
	select {
	case a.writeCh <- fn:
	case <-a.closed:
		fn()
	default:
		// Buffer full — write inline rather than lose the event.
		fn()
	}
}

// Flush blocks until all writes enqueued before this call have completed. It is
// the synchronization barrier for same-process read-after-write consumers: the
// proxy write path is fire-and-forget (Log/LogForensic only enqueue), so without
// a Flush a just-logged event may not yet be visible in SQLite. Used internally
// by SyncUnpushedLogs before it reads unsynced rows, and by callers that log then
// immediately query the same database.
func (a *AuditLogger) Flush() {
	select {
	case <-a.closed:
		return
	default:
	}
	done := make(chan struct{})
	select {
	case a.writeCh <- func() { close(done) }:
		<-done
	case <-a.closed:
	}
}

// DefaultLogPath returns the default audit database path: ~/.agentsecrets/audit.db
func DefaultLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".agentsecrets")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("cannot create config directory: %w", err)
	}
	return filepath.Join(dir, "audit.db"), nil
}

// NewAuditLogger creates an audit logger that connects to a local SQLite database.
func NewAuditLogger(dbPath string) (*AuditLogger, error) {
	if dbPath == "" {
		var err error
		dbPath, err = DefaultLogPath()
		if err != nil {
			return nil, err
		}
	}

	// Connect to SQLite
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	if flag.Lookup("test.v") != nil {
		_, _ = db.Exec("PRAGMA journal_mode=DELETE;")
		_, _ = db.Exec("PRAGMA synchronous=OFF;")
	} else {
		_, _ = db.Exec("PRAGMA journal_mode=WAL;")
		_, _ = db.Exec("PRAGMA synchronous=NORMAL;")
	}

	// Create table if it doesn't exist
	schemaTable := `
	CREATE TABLE IF NOT EXISTS audit_events (
		id TEXT PRIMARY KEY,
		timestamp DATETIME NOT NULL,
		environment TEXT,
		agent_id TEXT,
		identity_level TEXT,
		method TEXT,
		target_url TEXT,
		domain TEXT,
		status_code INTEGER,
		duration_ms INTEGER,
		status TEXT,
		reason TEXT,
		redacted BOOLEAN,
		resolution_path TEXT,
		caller_role TEXT,
		workspace_id TEXT,
		project_id TEXT,
		token_id TEXT,
		secret_keys TEXT,
		auth_styles TEXT,
		synced BOOLEAN DEFAULT 0
	);`
	if _, err := db.Exec(schemaTable); err != nil {
		return nil, fmt.Errorf("failed to initialize table: %w", err)
	}

	schemaForensic := `
	CREATE TABLE IF NOT EXISTS forensic_audit_events (
		id TEXT PRIMARY KEY,
		version TEXT,
		created_at DATETIME NOT NULL,
		workspace_id TEXT,
		project_id TEXT,
		environment TEXT,
		agent_id TEXT,
		token_id TEXT,
		domain TEXT,
		method TEXT,
		status_code INTEGER,
		outcome TEXT,
		latency_ms INTEGER,
		chain_hash TEXT,
		event_json TEXT,
		snapshot_json TEXT,
		enforcement_json TEXT,
		resolution_json TEXT,
		synced BOOLEAN DEFAULT 0
	);`
	if _, err := db.Exec(schemaForensic); err != nil {
		return nil, fmt.Errorf("failed to initialize forensic table: %w", err)
	}

	schemaForensicIndexes := `
	CREATE INDEX IF NOT EXISTS idx_forensic_created_at ON forensic_audit_events(created_at);
	CREATE INDEX IF NOT EXISTS idx_forensic_outcome ON forensic_audit_events(outcome);
	CREATE INDEX IF NOT EXISTS idx_forensic_domain ON forensic_audit_events(domain);
	`
	if _, err := db.Exec(schemaForensicIndexes); err != nil {
		return nil, fmt.Errorf("failed to initialize forensic indexes: %w", err)
	}

	// Apply schema migrations for older databases
	// SQLite ignores the error if the column already exists (or we just discard it)
	columns := []string{
		"environment",
		"agent_id",
		"identity_level",
		"workspace_id",
		"project_id",
		"token_id",
		"caller_role",
		"synced",
	}
	for _, col := range columns {
		var query string
		if col == "synced" {
			query = "ALTER TABLE audit_events ADD COLUMN synced BOOLEAN DEFAULT 0;"
		} else {
			query = fmt.Sprintf("ALTER TABLE audit_events ADD COLUMN %s TEXT;", col)
		}
		_, _ = db.Exec(query) // intentionally ignore error
	}

	schemaIndexes := `
	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent_id);
	CREATE INDEX IF NOT EXISTS idx_audit_domain ON audit_events(domain);
	CREATE INDEX IF NOT EXISTS idx_audit_environment ON audit_events(environment);
	`
	if _, err := db.Exec(schemaIndexes); err != nil {
		return nil, fmt.Errorf("failed to initialize indexes: %w", err)
	}

	a := &AuditLogger{db: db}
	a.startWriter()
	return a, nil
}

// Log writes a single audit event to the SQLite database asynchronously.
// Returns nil once the event is queued (or written synchronously if the
// buffer is full / the logger is shutting down).
func (a *AuditLogger) Log(event AuditEvent) error {
	if event.ID == "" {
		event.ID = "log_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	}
	keysJSON, _ := json.Marshal(event.SecretKeys)
	stylesJSON, _ := json.Marshal(event.AuthStyles)

	a.enqueue(func() {
		a.mu.Lock()
		defer a.mu.Unlock()

		query := `
		INSERT INTO audit_events (
			id, timestamp, environment, agent_id, identity_level, method, target_url,
			domain, status_code, duration_ms, status, reason, redacted,
			resolution_path, caller_role, workspace_id, project_id, token_id,
			secret_keys, auth_styles
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`

		_, _ = a.db.ExecContext(context.Background(), query,
			event.ID,
			event.Timestamp.UTC(), // Important standard for SQLite
			event.Environment,
			event.AgentID,
			event.IdentityLevel,
			event.Method,
			event.TargetURL,
			event.Domain,
			event.StatusCode,
			event.DurationMs,
			event.Status,
			event.Reason,
			event.Redacted,
			event.ResolutionPath,
			event.CallerRole,
			event.WorkspaceID,
			event.ProjectID,
			event.TokenID,
			string(keysJSON),
			string(stylesJSON),
		)
	})
	return nil
}

// SyncUnpushedLogs reads unsynced events from the database, pushes them to the cloud API,
// and marks them as synced if successful.
func (a *AuditLogger) SyncUnpushedLogs() error {
	if a.APIClient == nil {
		return nil // Cloud sync is not configured
	}
	if !config.IsAuthenticated() {
		return nil // Skip syncing if user has no active session
	}

	// Ensure all queued async writes have landed before we read unsynced rows,
	// so a just-logged event isn't missed by this sync pass.
	a.Flush()

	a.mu.Lock()
	defer a.mu.Unlock()

	var legacyPayload []map[string]interface{}
	var legacyIDs []string

	// 1. Fetch legacy / Tier 2 audit events
	rowsLegacy, err := a.db.Query(`
		SELECT id, timestamp, environment, agent_id, identity_level, method, target_url,
		       domain, status_code, duration_ms, status, reason, redacted, resolution_path,
		       caller_role, workspace_id, project_id, token_id, secret_keys, auth_styles
		FROM audit_events
		WHERE synced = 0
		LIMIT 100
	`)
	if err == nil {
		defer rowsLegacy.Close()
		for rowsLegacy.Next() {
			var e AuditEvent
			var keysJSON, stylesJSON string
			var ts time.Time

			err := rowsLegacy.Scan(
				&e.ID, &ts, &e.Environment, &e.AgentID, &e.IdentityLevel, &e.Method, &e.TargetURL,
				&e.Domain, &e.StatusCode, &e.DurationMs, &e.Status, &e.Reason, &e.Redacted, &e.ResolutionPath,
				&e.CallerRole, &e.WorkspaceID, &e.ProjectID, &e.TokenID, &keysJSON, &stylesJSON,
			)
			if err != nil {
				continue // skip broken rows
			}

			e.Timestamp = ts
			json.Unmarshal([]byte(keysJSON), &e.SecretKeys)
			json.Unmarshal([]byte(stylesJSON), &e.AuthStyles)

			targetPath := ""
			if u, err := url.Parse(e.TargetURL); err == nil {
				targetPath = u.Path
			}

			mapped := map[string]interface{}{
				"id":              e.ID,
				"schema_version":  1,
				"timestamp":       e.Timestamp.UTC().Format(time.RFC3339Nano),
				"environment":     e.Environment,
				"workspace_id":    e.WorkspaceID,
				"project_id":      e.ProjectID,
				"agent_id":        e.AgentID,
				"token_id":        e.TokenID,
				"identity_level":  e.IdentityLevel,
				"credential_ref":  strings.Join(e.SecretKeys, ","),
				"injection_style": strings.Join(e.AuthStyles, ","),
				"target_domain":   e.Domain,
				"target_url":      e.TargetURL,
				"target_path":     targetPath,
				"method":          e.Method,
				"status_code":     e.StatusCode,
				"duration_ms":     e.DurationMs,
				"redacted":        e.Redacted,
				"resolution_path": e.ResolutionPath,
				"caller_role":     e.CallerRole,
			}
			legacyPayload = append(legacyPayload, mapped)
			legacyIDs = append(legacyIDs, e.ID)
		}
	}

	// 2. Fetch Tier 3 forensic audit events
	var forensicPayload []map[string]interface{}
	var forensicIDs []string

	rowsForensic, err := a.db.Query(`
		SELECT id, version, created_at, workspace_id, project_id, environment, agent_id, 
		       token_id, domain, method, status_code, outcome, latency_ms, chain_hash,
		       event_json, snapshot_json, enforcement_json, resolution_json
		FROM forensic_audit_events
		WHERE synced = 0
		LIMIT 100
	`)
	if err == nil {
		defer rowsForensic.Close()
		for rowsForensic.Next() {
			var fe ForensicAuditEvent
			var eventJSON, snapshotJSON, enforcementJSON, resolutionJSON string
			var workspaceID, projectID, environment, agentID, tokenID, domain, method, outcome, chainHash sql.NullString
			var createdAt time.Time

			err := rowsForensic.Scan(
				&fe.ID,
				&fe.Version,
				&createdAt,
				&workspaceID,
				&projectID,
				&environment,
				&agentID,
				&tokenID,
				&domain,
				&method,
				&fe.Event.StatusCode,
				&outcome,
				&fe.Event.LatencyMs,
				&chainHash,
				&eventJSON,
				&snapshotJSON,
				&enforcementJSON,
				&resolutionJSON,
			)
			if err != nil {
				continue // skip broken rows
			}

			fe.CreatedAt = createdAt
			if workspaceID.Valid {
				fe.WorkspaceID = workspaceID.String
			}
			if projectID.Valid {
				fe.ProjectID = projectID.String
			}

			_ = json.Unmarshal([]byte(eventJSON), &fe.Event)
			_ = json.Unmarshal([]byte(snapshotJSON), &fe.Snapshot)
			_ = json.Unmarshal([]byte(enforcementJSON), &fe.Enforcement)
			_ = json.Unmarshal([]byte(resolutionJSON), &fe.Resolution)

			h := sha256.New()
			h.Write([]byte(eventJSON))
			h.Write([]byte(snapshotJSON))
			h.Write([]byte(enforcementJSON))
			h.Write([]byte(resolutionJSON))
			entryHash := fmt.Sprintf("%x", h.Sum(nil))

			chStr := ""
			if chainHash.Valid {
				chStr = chainHash.String
			}

			mappedForensic := map[string]interface{}{
				"id":               fe.ID,
				"workspace_id":     fe.WorkspaceID,
				"project_id":       fe.ProjectID,
				"created_at":       fe.CreatedAt.UTC().Format(time.RFC3339Nano),
				"stream_id":        "cli_" + fe.WorkspaceID,
				"stream_seq":       0,
				"chain_hash":       chStr,
				"entry_hash":       entryHash,
				"event_json":       fe.Event,
				"snapshot_json":    fe.Snapshot,
				"enforcement_json": fe.Enforcement,
				"resolution_json":  fe.Resolution,
			}
			forensicPayload = append(forensicPayload, mappedForensic)
			forensicIDs = append(forensicIDs, fe.ID)
		}
	}

	var syncErrors []error

	// 3. Push Tier 2 metadata to /api/internal/audit/logs/ ("audit.sync")
	if len(legacyPayload) > 0 {
		if err := a.APIClient.CallNoContent("audit.sync", "POST", legacyPayload, nil, nil); err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("audit.sync API call failed: %w", err))
		} else if len(legacyIDs) > 0 {
			placeholders := make([]string, len(legacyIDs))
			args := make([]interface{}, len(legacyIDs))
			for i, id := range legacyIDs {
				placeholders[i] = "?"
				args[i] = id
			}
			query := fmt.Sprintf("UPDATE audit_events SET synced = 1 WHERE id IN (%s)", strings.Join(placeholders, ","))
			if _, err := a.db.Exec(query, args...); err != nil {
				syncErrors = append(syncErrors, fmt.Errorf("failed to mark legacy audit logs as synced: %w", err))
			}
		}
	}

	// 4. Push Tier 3 forensic records to /api/internal/forensic/logs/ ("forensic.sync")
	if len(forensicPayload) > 0 {
		if err := a.APIClient.CallNoContent("forensic.sync", "POST", forensicPayload, nil, nil); err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("forensic.sync API call failed: %w", err))
		} else if len(forensicIDs) > 0 {
			placeholders := make([]string, len(forensicIDs))
			args := make([]interface{}, len(forensicIDs))
			for i, id := range forensicIDs {
				placeholders[i] = "?"
				args[i] = id
			}
			query := fmt.Sprintf("UPDATE forensic_audit_events SET synced = 1 WHERE id IN (%s)", strings.Join(placeholders, ","))
			if _, err := a.db.Exec(query, args...); err != nil {
				syncErrors = append(syncErrors, fmt.Errorf("failed to mark forensic audit logs as synced: %w", err))
			}
		}
	}

	if len(syncErrors) > 0 {
		return fmt.Errorf("sync errors: %v", syncErrors)
	}

	return nil
}

// Close drains any queued audit writes, stops the background writer, and closes
// the underlying database connection. Safe to call multiple times.
func (a *AuditLogger) Close() error {
	a.closeOnce.Do(func() {
		if a.closed != nil {
			close(a.closed)
		}
		a.wg.Wait()
	})
	if a.db != nil {
		return a.db.Close()
	}
	return nil
}

// DB returns the underlying database for querying.
func (a *AuditLogger) DB() *sql.DB {
	return a.db
}

// LogForensic writes a forensic audit event with snapshot state and a cryptographic hash chain.
//
// The write (previous-ID lookup, chain-hash computation, insert) runs on the
// single background writer goroutine, which guarantees the hash chain stays
// correctly ordered without blocking the caller (the proxy request path).
func (a *AuditLogger) LogForensic(event ForensicAuditEvent) error {
	if event.ID == "" {
		event.ID = "log_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	}
	if event.Version == "" {
		event.Version = "2"
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}

	a.enqueue(func() {
		a.mu.Lock()
		defer a.mu.Unlock()

		// 1. Get previous entry's ID to compute the chain hash
		prevID := "genesis_block"
		var lastID string
		err := a.db.QueryRowContext(context.Background(),
			"SELECT id FROM forensic_audit_events ORDER BY created_at DESC, id DESC LIMIT 1",
		).Scan(&lastID)
		if err == nil && lastID != "" {
			prevID = lastID
		}

		// 2. Compute chain hash: sha256(prevID + currentID + created_at_RFC3339)
		tsStr := event.CreatedAt.Format(time.RFC3339Nano)
		h := sha256.New()
		h.Write([]byte(prevID + event.ID + tsStr))
		event.ChainHash = fmt.Sprintf("%x", h.Sum(nil))

		// 3. Marshal nested blocks to JSON strings
		eventJSON, _ := json.Marshal(event.Event)
		snapshotJSON, _ := json.Marshal(event.Snapshot)
		enforcementJSON, _ := json.Marshal(event.Enforcement)
		resolutionJSON, _ := json.Marshal(event.Resolution)

		var agentID, tokenID string
		if event.Event.AgentIdentity != nil {
			agentID = event.Event.AgentIdentity.TokenName
			tokenID = event.Event.AgentIdentity.TokenID
		}

		// 4. Insert into DB
		query := `
		INSERT INTO forensic_audit_events (
			id, version, created_at, workspace_id, project_id, environment, agent_id,
			token_id, domain, method, status_code, outcome, latency_ms, chain_hash,
			event_json, snapshot_json, enforcement_json, resolution_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`
		_, _ = a.db.ExecContext(context.Background(), query,
			event.ID,
			event.Version,
			event.CreatedAt.UTC(),
			event.WorkspaceID,
			event.ProjectID,
			event.Event.Environment,
			agentID,
			tokenID,
			event.Event.Domain,
			event.Event.Method,
			event.Event.StatusCode,
			event.Event.Outcome,
			event.Event.LatencyMs,
			event.ChainHash,
			string(eventJSON),
			string(snapshotJSON),
			string(enforcementJSON),
			string(resolutionJSON),
		)
	})
	return nil
}

// LogManagementEvent logs a workspace management action to the local forensic database.
func LogManagementEvent(method, domain, path, userEmail, workspaceID, projectID, environment string) error {
	logger, err := NewAuditLogger("")
	if err != nil {
		return err
	}
	defer logger.Close()

	ev := ForensicAuditEvent{
		ID:          "log_" + strings.ReplaceAll(uuid.New().String(), "-", ""),
		Version:     "2",
		CreatedAt:   time.Now().UTC(),
		WorkspaceID: workspaceID,
		ProjectID:   projectID,
		Event: EventBlock{
			Type:        "management",
			Domain:      domain,
			Path:        path,
			Method:      method,
			StatusCode:  200,
			Outcome:     "success",
			Environment: environment,
			AgentIdentity: &AgentIdentity{
				TokenName:     userEmail,
				IdentityLevel: "user",
			},
		},
		Enforcement: EnforcementBlock{
			Decision:  "permitted",
			DecidedBy: "local cli",
		},
		Resolution: ResolutionBlock{
			ResponseStatus: 200,
		},
	}

	if err := logger.LogForensic(ev); err != nil {
		return err
	}

	// Try to sync management events immediately to the cloud if we can authenticate
	if apiClient := auth.NewAuthenticatedClient(); apiClient != nil {
		logger.APIClient = apiClient
		_ = logger.SyncUnpushedLogs()
	}

	return nil
}

