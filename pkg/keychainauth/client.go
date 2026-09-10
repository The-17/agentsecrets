package keychainauth

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/The-17/agentsecrets/pkg/telemetry"
)

// conn holds the persistent connection to the keychain-auth daemon.
// The connection itself is the authenticated session — no tokens needed.
var (
	conn          net.Conn
	scanner       *bufio.Scanner
	encoder       *json.Encoder
	sessionMu     sync.Mutex
	initialized   bool
	testStubMode  bool
	testStubStore map[string]string
	testStubMu    sync.RWMutex
)

// maxResponseBuffer bounds a single daemon response line. Prefix reads over a
// large project can return many secrets in one framed message, so the default
// bufio.Scanner cap (64KB) is too small and would surface as a bogus
// "connection lost". 10MB comfortably covers realistic keychain payloads.
const maxResponseBuffer = 10 * 1024 * 1024

// Init connects to the keychain-auth daemon.
//
// The daemon verifies the caller process at connection time using kernel-level
// peer credentials (PID, binary path, binary hash). If the binary is not
// registered, the daemon sends a denied response; that denial surfaces on the
// first real request (see sendRequest), so Init itself performs no probe or
// ping round-trip — it just establishes the connection.
//
// This must be called once per process lifetime before any secret operations.
func Init() error {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	return initLocked()
}

// initLocked performs connection setup while the caller already holds sessionMu.
// This lets sendRequest reconnect without an unlock/relock window.
func initLocked() error {
	if initialized {
		return nil
	}

	// Shred and delete legacy files on startup
	_ = PurgeLegacyFiles()

	sockPath := SocketPath()

	// Step 1: Check socket exists before attempting connection (Unix only)
	if runtime.GOOS != "windows" {
		if _, err := os.Stat(sockPath); os.IsNotExist(err) {
			return &DaemonNotRunningError{SocketPath: sockPath, Cause: err}
		}
	}

	// Step 2: Connect to the Unix socket with SOCK_CLOEXEC to prevent
	// file descriptor leakage to child processes (agentsecrets env/exec).
	c, err := dialCLOEXEC(sockPath)
	if err != nil {
		return &DaemonNotRunningError{SocketPath: sockPath, Cause: err}
	}

	// The daemon verifies us at connection time. If our binary is unregistered
	// it will send a status="denied" RESPONSE; rather than blocking on a read
	// deadline to detect that here, we let the denial surface on the first real
	// request (sendRequest maps "denied"/"error" to DaemonDeniedError). This
	// removes a fixed ~200ms probe from every process startup.
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 0, 64*1024), maxResponseBuffer)

	conn = c
	scanner = sc
	encoder = json.NewEncoder(c)
	initialized = true
	telemetry.RecordProcessVerificationsPassed()

	return nil
}

// resetConn tears down the current connection and clears session state.
// The caller must hold sessionMu. Centralizing this both prevents the
// file-descriptor leak (the old conn is always closed before a reconnect)
// and removes the repeated cleanup blocks that Init previously carried.
func resetConn() {
	if conn != nil {
		conn.Close()
	}
	conn = nil
	scanner = nil
	encoder = nil
	initialized = false
	// Drop cached metadata: a reconnect may span an external mutation, so
	// don't let a pre-reset listing/policy survive across it.
	valueCache.invalidateAll()
}

// Close tears down the Unix socket connection to keychain-auth.
// Safe to call multiple times. Should be deferred from main.
func Close() {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	resetConn()
}

// IsAvailable checks whether the keychain-auth socket file exists on disk.
// On Windows, it attempts to dial the named pipe to check availability.
func IsAvailable() bool {
	sockPath := SocketPath()
	c, err := dialCLOEXEC(sockPath)
	if err == nil {
		c.Close()
		return true
	}

	userSock := UserSocketPath()
	if userSock != sockPath {
		if c2, err2 := dialCLOEXEC(userSock); err2 == nil {
			c2.Close()
			return true
		}
	}

	// Clean up stale dead socket file if any
	if runtime.GOOS != "windows" {
		_ = os.Remove(sockPath)
		if userSock != sockPath {
			_ = os.Remove(userSock)
		}
	}
	return false
}

// IsInitialized returns true if a connection has been successfully established.
func IsInitialized() bool {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	return initialized
}

// Verify confirms the daemon still accepts this binary by issuing one lightweight
// request. The daemon checks our peer credentials (binary path + hash) before it
// evaluates the request itself, so an unregistered or hash-mismatched binary —
// e.g. one that was just upgraded — is denied here with a *DaemonDeniedError the
// caller can route into re-registration recovery, instead of letting the raw
// denial surface on the user's first real command.
//
// It performs a search (key names only — never a secret value) under a prefix
// that is not expected to match anything, so the request is cheap and side-effect
// free. This is used deliberately by callers that gate it (e.g. only after the
// binary changed); Init itself stays probe-free so the hot path pays nothing.
func Verify() error {
	_, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionSearch,
		Service: serviceName,
		Targets: []string{"__agentsecrets_verify__:"},
	})
	return err
}

// --- Secret CRUD operations ---

// SetSecret stores a secret in the OS keychain via keychain-auth.
func SetSecret(projectID, environment, key, value string) error {
	target := formatTarget(projectID, environment, key)
	_, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionWrite,
		Service: serviceName,
		Targets: []string{target},
		Values:  []string{value},
	})
	if err == nil {
		valueCache.invalidateAll()
	}
	return err
}

// SetSecretsBatch stores multiple secrets and their policies in a single round-trip.
// Each entry in secrets is a key-value pair; each entry in policies is the serialized
// policy JSON (or nil for no policy). The arrays must have the same length.
// Returns the number of successful writes and the first error encountered (if any).
func SetSecretsBatch(projectID, environment string, secrets map[string]string, policies map[string][]byte) (int, error) {
	if len(secrets) == 0 {
		return 0, nil
	}

	var targets []string
	var values []string

	// First pass: secrets
	for key, val := range secrets {
		targets = append(targets, formatTarget(projectID, environment, key))
		values = append(values, val)
	}

	// Second pass: policies
	for key, policyBytes := range policies {
		policyTarget := formatTarget(projectID, environment, key) + ":policy"
		if policyBytes == nil || len(policyBytes) == 0 {
			// Delete policy entry if nil/empty
			targets = append(targets, policyTarget)
			values = append(values, "")
		} else {
			targets = append(targets, policyTarget)
			values = append(values, string(policyBytes))
		}
	}

	_, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionWrite,
		Service: serviceName,
		Targets: targets,
		Values:  values,
	})
	if err == nil {
		valueCache.invalidateAll()
	}
	return len(secrets), err
}

// GetSecret retrieves a single secret from the OS keychain via keychain-auth.
// Plaintext secret values are never cached in-process — every read goes to the
// daemon so a rotation/revocation elsewhere is reflected immediately.
func GetSecret(projectID, environment, key string) (string, error) {
	target := formatTarget(projectID, environment, key)
	resp, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionRead,
		Service: serviceName,
		Targets: []string{target},
	})
	if err != nil {
		return "", err
	}
	if len(resp.Results) == 0 {
		return "", fmt.Errorf("secret %q not found", key)
	}
	return resp.Results[0].Value, nil
}

// DeleteSecret removes a secret from the OS keychain via keychain-auth.
func DeleteSecret(projectID, environment, key string) error {
	target := formatTarget(projectID, environment, key)
	_, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionDelete,
		Service: serviceName,
		Targets: []string{target},
	})
	if err == nil {
		valueCache.invalidateAll()
	}
	return err
}

// GetAllProjectSecrets returns all secrets for a project+environment as a
// key→value map. Uses a prefix read to fetch everything in a single round-trip.
// Values are never cached in-process (see GetSecret).
func GetAllProjectSecrets(projectID, environment string) (map[string]string, error) {
	prefix := formatPrefix(projectID, environment)
	resp, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionRead,
		Service: serviceName,
		Match:   matchPrefix,
		Targets: []string{prefix},
	})
	if err != nil {
		return nil, err
	}

	result := make(map[string]string, len(resp.Results))
	for _, item := range resp.Results {
		bare := stripPrefix(item.Target, prefix)
		if bare == "" {
			continue
		}
		// Skip metadata entries (e.g. "KEY:policy") — only return actual secrets.
		if strings.HasSuffix(bare, ":policy") {
			continue
		}
		result[bare] = item.Value
	}
	return result, nil
}

// ListProjectKeyNames returns just the key names for a project+environment.
// Uses a search operation — no secret values are read, so the result (key
// names only, no plaintext) is safe to serve from the short-lived cache.
func ListProjectKeyNames(projectID, environment string) ([]string, error) {
	prefix := formatPrefix(projectID, environment)
	ck := "names:" + serviceName + ":" + prefix
	if e, ok := valueCache.get(ck); ok {
		return append([]string(nil), e.listVal...), nil
	}
	resp, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionSearch,
		Service: serviceName,
		Targets: []string{prefix},
	})
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(resp.Results))
	for _, item := range resp.Results {
		bare := stripPrefix(item.Target, prefix)
		if bare == "" {
			continue
		}
		// Skip metadata entries (e.g. "KEY:policy") — only return actual secret keys.
		if strings.HasSuffix(bare, ":policy") {
			continue
		}
		keys = append(keys, bare)
	}
	valueCache.put(ck, cacheEntry{listVal: append([]string(nil), keys...)})
	return keys, nil
}

// SetWorkspaceAllowlist stores the domain allowlist for a workspace.
func SetWorkspaceAllowlist(workspaceID string, domains []string) error {
	target := formatAllowlistTarget(workspaceID)
	valBytes, err := json.Marshal(domains)
	if err != nil {
		return fmt.Errorf("serialize allowlist: %w", err)
	}
	_, err = sendRequest(request{
		Type:    typeRequest,
		Action:  actionWrite,
		Service: serviceName,
		Targets: []string{target},
		Values:  []string{string(valBytes)},
	})
	if err == nil {
		valueCache.invalidateAll()
	}
	return err
}

// GetWorkspaceAllowlist retrieves the domain allowlist for a workspace.
// The allowlist is non-secret (a list of permitted domains), so it is served
// from the short-lived cache to avoid re-resolving it on every proxy call and
// again in the forensic audit path for the same request.
func GetWorkspaceAllowlist(workspaceID string) ([]string, error) {
	target := formatAllowlistTarget(workspaceID)
	ck := "allow:" + serviceName + ":" + target
	if e, ok := valueCache.get(ck); ok {
		return append([]string(nil), e.listVal...), nil
	}
	resp, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionRead,
		Service: serviceName,
		Targets: []string{target},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Results) == 0 {
		return []string{}, nil
	}

	var domains []string
	if err := json.Unmarshal([]byte(resp.Results[0].Value), &domains); err != nil {
		return nil, fmt.Errorf("parse allowlist: %w", err)
	}
	valueCache.put(ck, cacheEntry{listVal: append([]string(nil), domains...)})
	return domains, nil
}

// SetSecretPolicy stores policy in the OS keychain via keychain-auth.
func SetSecretPolicy(projectID, environment, key string, policy []byte) error {
	target := formatTarget(projectID, environment, key) + ":policy"
	_, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionWrite,
		Service: serviceName,
		Targets: []string{target},
		Values:  []string{string(policy)},
	})
	if err == nil {
		valueCache.invalidateAll()
	}
	return err
}

// GetSecretPolicy retrieves policy from the OS keychain via keychain-auth.
func GetSecretPolicy(projectID, environment, key string) ([]byte, error) {
	target := formatTarget(projectID, environment, key) + ":policy"
	ck := "pol:" + serviceName + ":" + target
	if e, ok := valueCache.get(ck); ok {
		return e.bytesVal, nil
	}
	resp, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionRead,
		Service: serviceName,
		Targets: []string{target},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Results) == 0 {
		return nil, nil
	}
	val := []byte(resp.Results[0].Value)
	valueCache.put(ck, cacheEntry{bytesVal: val})
	return val, nil
}

// --- Internal helpers ---

// sendRequest sends a request to the daemon and reads the response.
//
// A registration denial (unregistered binary, or a hash that changed because
// agentsecrets was just upgraded) is repaired transparently and the request is
// retried once. This is the difference between a user seeing a brief
// "re-authorizing" notice and a user being handed shell commands to run by hand:
// the denial surfaces here, at request time, not during Init, so recovery has to
// live at this seam.
//
// The caller must NOT hold sessionMu.
func sendRequest(req request) (*response, error) {
	resp, err := sendRequestOnce(req)
	if err == nil || !isRegistrationDenial(err) {
		return resp, err
	}

	if repairErr := tryRegistrationRepair(); repairErr != nil {
		// Repair was unavailable or failed — surface the original denial, which
		// carries the actionable reason code.
		return nil, err
	}
	return sendRequestOnce(req)
}

// sendRequestOnce performs a single request/response exchange, reconnecting once if
// the connection is half-open. It does not attempt registration repair.
// The caller must NOT hold sessionMu.
func sendRequestOnce(req request) (*response, error) {
	sessionMu.Lock()
	testMode := testStubMode
	if testMode {
		sessionMu.Unlock()
		return handleStubRequest(req)
	}
	defer sessionMu.Unlock()

	// Helper to ensure the connection is live. initLocked is a no-op when
	// already initialized, so this is cheap on the happy path.
	ensureConn := func() error {
		if err := initLocked(); err != nil {
			return fmt.Errorf("keychainauth: not initialized (failed to auto-reconnect: %w)", err)
		}
		return nil
	}

	if err := ensureConn(); err != nil {
		return nil, err
	}

	req.Type = typeRequest

	// Try sending request. If it fails, reset the (possibly half-open)
	// connection, reconnect once, and retry.
	if err := encoder.Encode(req); err != nil {
		resetConn()
		if reconnectErr := ensureConn(); reconnectErr != nil {
			return nil, fmt.Errorf("keychainauth: failed to send request: %w (reconnect failed: %v)", err, reconnectErr)
		}
		if err = encoder.Encode(req); err != nil {
			resetConn()
			return nil, fmt.Errorf("keychainauth: failed to send request on retry: %w", err)
		}
	}

	// Read response. If it fails, reset, reconnect once, and retry the whole request.
	if !scanner.Scan() {
		scanErr := scanner.Err()
		resetConn()
		if reconnectErr := ensureConn(); reconnectErr != nil {
			if scanErr != nil {
				return nil, fmt.Errorf("keychainauth: connection lost: %w (reconnect failed: %v)", scanErr, reconnectErr)
			}
			return nil, fmt.Errorf("keychainauth: connection closed by daemon (reconnect failed: %v)", reconnectErr)
		}
		if err := encoder.Encode(req); err != nil {
			resetConn()
			return nil, fmt.Errorf("keychainauth: failed to resend request on retry: %w", err)
		}
		if !scanner.Scan() {
			retryErr := scanner.Err()
			resetConn()
			if retryErr != nil {
				return nil, fmt.Errorf("keychainauth: connection lost on retry: %w", retryErr)
			}
			return nil, fmt.Errorf("keychainauth: connection closed by daemon on retry")
		}
	}

	var resp response
	raw := scanner.Bytes()
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("keychainauth: invalid response: %w", err)
	}

	switch resp.Status {
	case "success":
		return &resp, nil
	case "denied":
		return nil, &DaemonDeniedError{Reason: resp.Reason}
	case "error":
		return nil, &DaemonDeniedError{Reason: resp.Reason}
	default:
		return nil, fmt.Errorf("keychainauth: unexpected response status %q", resp.Status)
	}
}

func formatTarget(projectID, environment, key string) string {
	if environment == "" {
		environment = "development"
	}
	return fmt.Sprintf("%s:%s:%s", projectID, environment, key)
}

func formatPrefix(projectID, environment string) string {
	if environment == "" {
		environment = "development"
	}
	return fmt.Sprintf("%s:%s:", projectID, environment)
}

func formatAllowlistTarget(workspaceID string) string {
	return fmt.Sprintf("agentsecrets:allowlist:%s", workspaceID)
}

func stripPrefix(target, prefix string) string {
	if strings.HasPrefix(target, prefix) {
		return target[len(prefix):]
	}
	return ""
}

// Write writes a value to a service/target namespace in the OS keychain via the daemon.
func Write(service, target, value string) error {
	_, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionWrite,
		Service: service,
		Targets: []string{target},
		Values:  []string{value},
	})
	if err == nil {
		valueCache.invalidateAll()
	}
	return err
}

// Read retrieves a single value for a service/target from the OS keychain via the daemon.
func Read(service, target string) (string, error) {
	resp, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionRead,
		Service: service,
		Targets: []string{target},
	})
	if err != nil {
		return "", err
	}
	if len(resp.Results) == 0 {
		return "", fmt.Errorf("keychainauth: target %q not found", target)
	}
	return resp.Results[0].Value, nil
}

// Delete removes a service/target entry from the OS keychain via the daemon.
func Delete(service, target string) error {
	_, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionDelete,
		Service: service,
		Targets: []string{target},
	})
	if err == nil {
		valueCache.invalidateAll()
	}
	return err
}

// Search returns a list of target keys registered under a service namespace that start with a prefix.
func Search(service, prefix string) ([]string, error) {
	resp, err := sendRequest(request{
		Type:    typeRequest,
		Action:  actionSearch,
		Service: service,
		Targets: []string{prefix},
	})
	if err != nil {
		return nil, err
	}
	results := make([]string, 0, len(resp.Results))
	for _, r := range resp.Results {
		results = append(results, r.Target)
	}
	return results, nil
}

// SetupTestStub enables an in-memory client stub for running unit tests without a running daemon.
func SetupTestStub() {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	testStubMode = true
	testStubStore = make(map[string]string)
	initialized = true
}

// TeardownTestStub disables the in-memory client stub and clears test store data.
func TeardownTestStub() {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	testStubMode = false
	testStubStore = nil
	initialized = false
}

func handleStubRequest(req request) (*response, error) {
	testStubMu.Lock()
	defer testStubMu.Unlock()

	resp := &response{
		Type:   typeResponse,
		Status: "success",
	}

	switch req.Action {
	case actionRead:
		for _, target := range req.Targets {
			key := req.Service + ":" + target
			if val, ok := testStubStore[key]; ok {
				resp.Results = append(resp.Results, resultItem{
					Target: target,
					Value:  val,
				})
			}
		}
	case actionWrite:
		for i, target := range req.Targets {
			key := req.Service + ":" + target
			testStubStore[key] = req.Values[i]
		}
	case actionDelete:
		for _, target := range req.Targets {
			key := req.Service + ":" + target
			delete(testStubStore, key)
		}
	case actionSearch:
		if len(req.Targets) > 0 {
			prefix := req.Targets[0]
			for k, val := range testStubStore {
				if strings.HasPrefix(k, req.Service+":") {
					target := strings.TrimPrefix(k, req.Service+":")
					if strings.HasPrefix(target, prefix) {
						resp.Results = append(resp.Results, resultItem{
							Target: target,
							Value:  val,
						})
					}
				}
			}
		}
	}

	return resp, nil
}
