package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/The-17/agentsecrets/pkg/capabilities"
)

// MaxRequestBodySize bounds the maximum request payload accepted by the proxy (10MB).
const MaxRequestBodySize = 10 * 1024 * 1024

// Server is the HTTP proxy server that wraps the Engine.
// It listens for incoming requests with X-AS-* headers, builds
// CallRequests, executes them through the engine, and returns responses.
type Server struct {
	Port   int
	Engine *Engine
	mux    *http.ServeMux
	wg     sync.WaitGroup

	// tokenMu guards SessionToken: it is read by every request handler and
	// written by handleRotateSession, so concurrent access must be synchronized.
	tokenMu      sync.RWMutex
	SessionToken string
}

// GetSessionToken returns the current session token ("" when unset).
func (s *Server) GetSessionToken() string {
	s.tokenMu.RLock()
	defer s.tokenMu.RUnlock()
	return s.SessionToken
}

// SetSessionToken sets the session token. Used at startup (the CLI generates
// the initial token) — rotation goes through handleRotateSession, which
// generates the new token server-side.
func (s *Server) SetSessionToken(token string) {
	s.tokenMu.Lock()
	s.SessionToken = token
	s.tokenMu.Unlock()
}

// rotateSessionToken generates a fresh token server-side, stores it, and
// returns it. The client never supplies the new token — trusting a client
// would let an attacker who can reach the endpoint pick their own session key.
func (s *Server) rotateSessionToken() (string, error) {
	newToken, err := GenerateSessionToken()
	if err != nil {
		return "", err
	}
	s.tokenMu.Lock()
	s.SessionToken = newToken
	s.tokenMu.Unlock()
	return newToken, nil
}

// NewServer creates a proxy server bound to the given port and engine.
func NewServer(port int, engine *Engine) *Server {
	s := &Server{
		Port:   port,
		Engine: engine,
		mux:    http.NewServeMux(),
	}
	s.mux.HandleFunc("/proxy", s.validateSession(s.handleProxy))
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/sync", s.validateSession(s.handleSync))
	s.mux.HandleFunc("/approve", s.validateSession(s.handleApprove))
	s.mux.HandleFunc("/rotate-session", s.validateSession(s.handleRotateSession))
	return s
}

func (s *Server) validateSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expected := s.GetSessionToken()
		if expected == "" {
			// No session token means no one can prove they are the local
			// client. Fail closed instead of letting the request through:
			// an empty token used to turn every endpoint into an open door.
			writeError(w, http.StatusServiceUnavailable, "proxy session token is not initialized")
			return
		}
		token := r.Header.Get("X-AS-Session-Token")
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			writeError(w, http.StatusUnauthorized, "Invalid or missing session token")
			return
		}
		next(w, r)
	}
}

// Start begins listening and serving. It blocks until ctx is cancelled (e.g.
// on SIGINT/SIGTERM) or the server fails to serve. On cancellation it performs
// a graceful shutdown: it stops accepting new connections, drains in-flight
// requests within a bounded window, and waits for background workers to exit
// before returning.
func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf("127.0.0.1:%d", s.Port)

	// Launch background sync worker if audit logger is present.
	if s.Engine.Audit != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			runPeriodic(ctx, 60*time.Second, s.Engine.Audit.SyncUnpushedLogs)
		}()
	}

	// Fetch the revocation list on startup and refresh it periodically so
	// revoked agent tokens stop working without a daemon restart.
	_ = s.Engine.Sync()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		runPeriodic(ctx, 60*time.Second, s.Engine.Sync)
	}()

	// Bind synchronously so a failed bind (port already in use) surfaces as an
	// error from Start rather than being lost inside the serve goroutine.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	httpServer := &http.Server{Handler: s.mux}
	errCh := make(chan error, 1)
	go func() {
		// Serve returns ErrServerClosed after a graceful Shutdown; that path is
		// handled below via ctx.Done(), so only unexpected errors reach errCh.
		errCh <- httpServer.Serve(ln)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := httpServer.Shutdown(shutdownCtx)
		s.wg.Wait() // Drain background workers cleanly
		return err
	}
}

// runPeriodic invokes fn periodically with randomized jitter (±20%) until ctx is cancelled.
func runPeriodic(ctx context.Context, interval time.Duration, fn func() error) {
	for {
		// Apply ±20% randomized jitter to prevent thundering herd spikes across daemons
		jitterRange := int64(interval / 5)
		var jitter time.Duration
		if jitterRange > 0 {
			jitter = time.Duration(rand.Int63n(jitterRange*2) - jitterRange)
		}
		timer := time.NewTimer(interval + jitter)

		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			_ = fn()
		}
	}
}

// handleHealth is a simple health check endpoint.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	lastSync, revoked := s.Engine.GetState()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"project":       s.Engine.ProjectID,
		"last_sync":     lastSync.Format(time.RFC3339),
		"revoked_count": len(revoked),
		"revoked_ids":   revoked,
	})
}

// handleSync forces an immediate revocation list sync.
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if err := s.Engine.Sync(); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("revocation sync failed: %v", err))
		return
	}

	lastSync, revoked := s.Engine.GetState()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"message":       "revocation sync triggered",
		"last_sync":     lastSync.Format(time.RFC3339),
		"revoked_count": len(revoked),
		"revoked_ids":   revoked,
	})
}

// handleProxy processes incoming proxy requests.
//
// Required headers:
//   - X-AS-Target-URL: The upstream URL to call
//
// Injection headers (at least one required):
//   - X-AS-Inject-Bearer: SECRET_KEY          → Authorization: Bearer <value>
//   - X-AS-Inject-Basic: SECRET_KEY           → Authorization: Basic base64(<value>)
//   - X-AS-Inject-Header: Name=SECRET_KEY     → Name: <value>
//   - X-AS-Inject-Query: param=SECRET_KEY     → ?param=<value>
//   - X-AS-Inject-Body: json.path=SECRET_KEY  → body.json.path = <value>
//   - X-AS-Inject-Form: field=SECRET_KEY      → form field = <value>
//
// The targeted styles carry the target in the header value because header
// names are canonicalised, which used to rewrite "channel" as "Channel" and
// "x-request-id" as "X.Request.Id". They are repeatable. The legacy
// X-AS-Inject-Query-<Param> name form is still accepted.
//
// Optional headers:
//   - X-AS-Method: HTTP method (default: GET)
//   - X-AS-Agent-ID: Agent identifier for audit logging
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	targetURL := r.Header.Get("X-AS-Target-URL")
	if targetURL == "" {
		writeError(w, 400, "X-AS-Target-URL header is required")
		return
	}

	method := r.Header.Get("X-AS-Method")
	if method == "" {
		method = r.Method
	}

	agentID := r.Header.Get("X-AS-Agent-ID")
	agentToken := r.Header.Get("X-AS-Agent-Token")

	injections, err := parseInjections(r.Header)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	// A request with no injection is still valid when it carries a body (a
	// literal POST, as the runbook exercises). The final check runs after the
	// body is read below, where "nothing to send" can be decided reliably.

	identityLevel := "anonymous"
	tokenID := ""
	var callReqCaps *capabilities.AgentCapabilities

	// Resolve/validate agent identity and enforce revocation + scope. This is the
	// SAME decision logic the engine uses (Engine.resolveIdentity) — the server
	// just maps the verdict to its own HTTP responses: a validation failure → 401,
	// a scope/revocation block → 403. Unlike before, a block now also emits an
	// audit record (via Engine.auditBlocked) so denials at the server layer are no
	// longer invisible to the forensic log.
	idr := s.Engine.resolveIdentity(CallRequest{
		AgentID:    agentID,
		AgentToken: agentToken,
		Injections: injections,
	})
	switch idr.Outcome {
	case identityError:
		writeError(w, 401, idr.Err.Error())
		return
	case identityBlocked:
		// Emit the same blocked-audit record the engine would, then return the
		// server's existing 403 body ({"error": msg}) unchanged. Derive domain/
		// path the same way the engine does (url.Parse + lowercased Hostname);
		// best-effort, since a malformed URL would be rejected downstream anyway.
		domain, path := "", ""
		if pu, perr := url.Parse(targetURL); perr == nil {
			domain = strings.ToLower(pu.Hostname())
			path = pu.Path
		}
		allKeys := make([]string, 0, len(injections))
		allStyles := make([]string, 0, len(injections))
		for _, inj := range injections {
			allKeys = append(allKeys, inj.SecretKey)
			allStyles = append(allStyles, inj.Style)
		}
		auditReq := CallRequest{
			TargetURL:     targetURL,
			AgentID:       agentID,
			IdentityLevel: "issued",
			TokenID:       idr.ResolvedTokenID,
		}
		s.Engine.auditBlocked(auditReq, domain, method, path, idr.Reason, idr.Message, allKeys, allStyles)
		writeError(w, 403, idr.Message)
		return
	case identityOK:
		if idr.ResolvedToken != "" {
			identityLevel = "issued"
			tokenID = idr.ResolvedTokenID
			if idr.ResolvedCapabilities != nil {
				if agentID == "" {
					agentID = idr.ResolvedAgentID
				}
				callReqCaps = idr.ResolvedCapabilities
			}
		} else if agentID != "" {
			identityLevel = "declared"
		}
	}

	// Read request body with maximum memory limit (10MB)
	var body []byte
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodySize)
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			writeError(w, 400, fmt.Sprintf("Failed to read request body: %v", err))
			return
		}
	}

	// Build extra headers (everything that's not X-AS-*)
	// Go's http.Header canonicalizes keys to "X-As-..." form
	headers := make(map[string]string)
	for k, v := range r.Header {
		if !strings.HasPrefix(k, "X-As-") {
			headers[k] = v[0]
		}
	}

	// Execute through engine with request context
	result, err := s.Engine.ExecuteCtx(r.Context(), CallRequest{
		TargetURL:     targetURL,
		Method:        method,
		Headers:       headers,
		Body:          body,
		Injections:    injections,
		AgentID:       agentID,
		IdentityLevel: identityLevel,
		TokenID:       tokenID,
		Capabilities:  callReqCaps,
	})

	if err != nil {
		writeError(w, 502, err.Error())
		return
	}

	// Forward upstream response
	for k, vals := range result.Headers {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(result.StatusCode)
	w.Write(result.Body)
}

// parseInjections extracts X-AS-Inject-* headers and converts them to
// Injections. It accepts two shapes:
//
//   - targeted: "X-AS-Inject-Query: channel=SECRET_KEY", the target in the
//     value (repeatable). Case and punctuation survive, because header values
//     are not canonicalised.
//   - legacy: "X-AS-Inject-Query-channel: SECRET_KEY", the target in the
//     header name. Kept so older clients and published curl recipes keep
//     working; note that Go canonicalisation mangles these names.
//
// A targeted header whose value has no "=" is a client bug, so it is reported
// instead of being dropped silently.
func parseInjections(headers http.Header) ([]Injection, error) {
	var injections []Injection

	for key, values := range headers {
		switch {
		case strings.EqualFold(key, "X-As-Inject-Bearer"):
			injections = append(injections, Injection{Style: "bearer", SecretKey: values[0]})

		case strings.EqualFold(key, "X-As-Inject-Basic"):
			injections = append(injections, Injection{Style: "basic", SecretKey: values[0]})

		case strings.EqualFold(key, "X-As-Inject-Header"),
			strings.EqualFold(key, "X-As-Inject-Query"),
			strings.EqualFold(key, "X-As-Inject-Body"),
			strings.EqualFold(key, "X-As-Inject-Form"):
			style := strings.ToLower(strings.TrimPrefix(strings.ToLower(key), "x-as-inject-"))
			for _, v := range values {
				target, secretKey, ok := strings.Cut(v, "=")
				if !ok {
					// The published docs used a space separator. Accept it so an
					// existing script keeps working.
					target, secretKey, ok = strings.Cut(v, " ")
				}
				target = strings.TrimSpace(target)
				secretKey = strings.TrimSpace(secretKey)
				if !ok || target == "" || secretKey == "" {
					return nil, fmt.Errorf("%s value must be target=SECRET_KEY, got %q", key, v)
				}
				injections = append(injections, Injection{Style: style, Target: target, SecretKey: secretKey})
			}

		case strings.HasPrefix(strings.ToLower(key), "x-as-inject-header-"):
			headerName := key[len("X-As-Inject-Header-"):]
			injections = append(injections, Injection{Style: "header", Target: headerName, SecretKey: values[0]})

		case strings.HasPrefix(strings.ToLower(key), "x-as-inject-query-"):
			paramName := key[len("X-As-Inject-Query-"):]
			injections = append(injections, Injection{Style: "query", Target: paramName, SecretKey: values[0]})

		case strings.HasPrefix(strings.ToLower(key), "x-as-inject-body-"):
			path := key[len("X-As-Inject-Body-"):]
			// Legacy encoding: dots were sent as dashes. A real hyphen cannot be
			// distinguished here, which is why the targeted form exists.
			path = strings.ReplaceAll(path, "-", ".")
			injections = append(injections, Injection{Style: "body", Target: path, SecretKey: values[0]})

		case strings.HasPrefix(strings.ToLower(key), "x-as-inject-form-"):
			formKey := key[len("X-As-Inject-Form-"):]
			injections = append(injections, Injection{Style: "form", Target: formKey, SecretKey: values[0]})
		}
	}

	return injections, nil
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

// handleApprove grants a session-based approval for a secret+domain+method combination.
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "POST required")
		return
	}

	var req struct {
		SecretKey string `json:"secret_key"`
		Method    string `json:"method"`
		Domain    string `json:"domain"`
		AgentID   string `json:"agent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "Invalid JSON body")
		return
	}

	if req.SecretKey == "" || req.Method == "" || req.Domain == "" {
		writeError(w, 400, "secret_key, method, and domain are required")
		return
	}

	if s.Engine.Approvals == nil {
		writeError(w, 500, "Approval store not initialized")
		return
	}

	key := ApprovalKey{
		AgentID:   req.AgentID,
		SecretKey: strings.ToUpper(req.SecretKey),
		Domain:    strings.ToLower(req.Domain),
		Method:    strings.ToUpper(req.Method),
	}
	s.Engine.Approvals.Approve(key)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "approved",
		"secret_key": key.SecretKey,
		"method":     key.Method,
		"domain":     key.Domain,
	})
}

// handleRotateSession rotates the server's session token. The new token is
// generated server-side (never trusted from the request body) and returned so
// the CLI can persist it to the keyring.
func (s *Server) handleRotateSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	// Drain the body so the request can be fully consumed regardless of payload.
	_, _ = io.Copy(io.Discard, r.Body)

	newToken, err := s.rotateSessionToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate new session token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "ok",
		"message":    "session token rotated successfully",
		"new_token":  newToken,
	})
}

func maskToken(token string) string {
	if token == "" {
		return ""
	}
	if strings.HasPrefix(token, "agt_") {
		return token // DB IDs are safe to log in full
	}
	if len(token) <= 10 {
		return "[REDACTED]"
	}
	return token[:6] + "..." + token[len(token)-4:]
}
