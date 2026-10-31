package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/The-17/agentsecrets/pkg/capabilities"
)

// mockResolver returns a resolver that maps key names to values.
func mockResolver(secrets map[string]string) SecretResolver {
	return func(key string) (string, error) {
		val, ok := secrets[key]
		if !ok {
			return "", fmt.Errorf("secret not found: %s", key)
		}
		return val, nil
	}
}

// mockAllowlist returns a resolver that returns the given domains (or common test domains if empty).
func mockAllowlist(domains ...string) AllowlistResolver {
	return func(workspaceID string) ([]string, error) {
		if len(domains) == 0 {
			return []string{"127.0.0.1", "localhost", "api.example.com", "example.com", "blocked.com", "approved.com"}, nil
		}
		return domains, nil
	}
}

func TestEngineExecuteBearer(t *testing.T) {
	// Upstream echo server — returns what it received
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer sk_test_123" {
			t.Errorf("upstream got Authorization = %q, want %q", auth, "Bearer sk_test_123")
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ok": true}`))
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		Client:           upstream.Client(),
		ResolveSecret:    mockResolver(map[string]string{"STRIPE_KEY": "sk_test_123"}),
		ResolveAllowlist: mockAllowlist(),
	}

	result, err := engine.Execute(CallRequest{
		TargetURL: upstream.URL + "/v1/charges",
		Method:    "POST",
		Body:      []byte(`{"amount": 1000}`),
		Injections: []Injection{
			{Style: "bearer", SecretKey: "STRIPE_KEY"},
		},
	})

	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.StatusCode)
	}
	if string(result.Body) != `{"ok": true}` {
		t.Errorf("Body = %q, want %q", string(result.Body), `{"ok": true}`)
	}
}

func TestEngineExecuteMultipleInjections(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Org-ID") != "org-abc" {
			t.Errorf("missing X-Org-ID header")
		}
		if r.Header.Get("X-API-Key") != "key-xyz" {
			t.Errorf("missing X-API-Key header")
		}
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID: "test-project",
		Client:    upstream.Client(),
		ResolveSecret: mockResolver(map[string]string{
			"ORG_ID":  "org-abc",
			"API_KEY": "key-xyz",
		}),
		ResolveAllowlist: mockAllowlist(),
	}

	result, err := engine.Execute(CallRequest{
		TargetURL: upstream.URL + "/data",
		Method:    "GET",
		Injections: []Injection{
			{Style: "header", Target: "X-Org-ID", SecretKey: "ORG_ID"},
			{Style: "header", Target: "X-API-Key", SecretKey: "API_KEY"},
		},
	})

	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.StatusCode)
	}
}

func TestEngineExecuteQueryInjection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("api_key")
		if key != "gmap-key-123" {
			t.Errorf("query param api_key = %q, want %q", key, "gmap-key-123")
		}
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		Client:           upstream.Client(),
		ResolveSecret:    mockResolver(map[string]string{"GMAP_KEY": "gmap-key-123"}),
		ResolveAllowlist: mockAllowlist(),
	}

	result, err := engine.Execute(CallRequest{
		TargetURL: upstream.URL + "/maps",
		Method:    "GET",
		Injections: []Injection{
			{Style: "query", Target: "api_key", SecretKey: "GMAP_KEY"},
		},
	})

	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.StatusCode)
	}
}

func TestEngineExecuteMissingSecret(t *testing.T) {
	engine := &Engine{
		ProjectID:        "test-project",
		Client:           http.DefaultClient,
		ResolveSecret:    mockResolver(map[string]string{}), // no secrets
		ResolveAllowlist: mockAllowlist(),
	}

	_, err := engine.Execute(CallRequest{
		TargetURL: "https://api.example.com",
		Method:    "GET",
		Injections: []Injection{
			{Style: "bearer", SecretKey: "MISSING_KEY"},
		},
	})

	if err == nil {
		t.Fatal("expected error for missing secret")
	}
}

func TestEngineExecuteMissingURL(t *testing.T) {
	engine := &Engine{
		ProjectID:        "test-project",
		Client:           http.DefaultClient,
		ResolveSecret:    mockResolver(map[string]string{}),
		ResolveAllowlist: mockAllowlist(),
	}

	_, err := engine.Execute(CallRequest{
		TargetURL:  "",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "KEY"}},
	})

	if err == nil {
		t.Fatal("expected error for missing URL")
	}
}

func TestEngineExecuteNoInjections(t *testing.T) {
	engine := &Engine{
		ProjectID:        "test-project",
		Client:           http.DefaultClient,
		ResolveSecret:    mockResolver(map[string]string{}),
		ResolveAllowlist: mockAllowlist(),
	}

	_, err := engine.Execute(CallRequest{
		TargetURL:  "https://api.example.com",
		Method:     "GET",
		Injections: []Injection{},
	})

	if err == nil {
		t.Fatal("expected error for no injections")
	}
}

func TestEngineExecuteExtraHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want %q", r.Header.Get("Content-Type"), "application/json")
		}
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		Client:           upstream.Client(),
		ResolveSecret:    mockResolver(map[string]string{"KEY": "val"}),
		ResolveAllowlist: mockAllowlist(),
	}

	result, err := engine.Execute(CallRequest{
		TargetURL: upstream.URL,
		Method:    "POST",
		Headers:   map[string]string{"Content-Type": "application/json"},
		Body:      []byte(`{"data": true}`),
		Injections: []Injection{
			{Style: "bearer", SecretKey: "KEY"},
		},
	})

	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.StatusCode)
	}
}

func TestAuditNeverLogsSecretValues(t *testing.T) {
	// Create temp log file
	tmpFile, err := os.CreateTemp("", "proxy-audit-test-*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	audit, err := NewAuditLogger(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	defer audit.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	secretValue := "sk_live_SUPER_SECRET_VALUE_12345"

	engine := &Engine{
		ProjectID:        "test-project",
		Client:           upstream.Client(),
		Audit:            audit,
		ResolveSecret:    mockResolver(map[string]string{"STRIPE_KEY": secretValue}),
		ResolveAllowlist: mockAllowlist(),
	}

	_, err = engine.Execute(CallRequest{
		TargetURL: upstream.URL + "/v1/charges",
		Method:    "POST",
		Injections: []Injection{
			{Style: "bearer", SecretKey: "STRIPE_KEY"},
		},
		AgentID: "test-agent",
	})
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	// Read the audit log
	logBytes, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	logContent := string(logBytes)

	// The secret VALUE must NEVER appear in the log
	if strings.Contains(logContent, secretValue) {
		t.Fatal("SECURITY: secret VALUE was found in audit log!")
	}

	// The secret KEY NAME should appear
	if !strings.Contains(logContent, "STRIPE_KEY") {
		t.Error("expected secret KEY NAME to appear in audit log")
	}

	// The agent ID should appear
	if !strings.Contains(logContent, "test-agent") {
		t.Error("expected agent ID to appear in audit log")
	}
}

func TestEngineExecuteRedactBody(t *testing.T) {
	secretValue := "sk_live_ECHO_SECRET_12345"
	originalResponse := fmt.Sprintf(`{"auth": "Bearer %s", "data": "hello"}`, secretValue)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(originalResponse))
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		ResolveAllowlist: mockAllowlist(),
		Client:           upstream.Client(),
		ResolveSecret:    mockResolver(map[string]string{"STRIPE_KEY": secretValue}),
	}

	result, err := engine.Execute(CallRequest{
		TargetURL: upstream.URL + "/data",
		Method:    "GET",
		Injections: []Injection{
			{Style: "bearer", SecretKey: "STRIPE_KEY"},
		},
	})

	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if result.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.StatusCode)
	}

	bodyStr := string(result.Body)
	if strings.Contains(bodyStr, secretValue) {
		t.Fatal("SECURITY: secret VALUE was found in response body!")
	}

	if !strings.Contains(bodyStr, "[REDACTED_BY_AGENTSECRETS]") {
		t.Error("expected response body to contain [REDACTED_BY_AGENTSECRETS]")
	}
}

// TestEngineExecuteRedactHeaders locks down that echoed secrets are stripped
// from response HEADERS too — not just the body. Upstreams reflect credentials
// in headers all the time (Set-Cookie, WWW-Authenticate, echoed API-key
// headers, tokens in a redirect Location). Only the engine holds the resolved
// value, so if it doesn't redact headers, the value leaks to every downstream
// consumer (CLI text mode discards headers today, but `--output json` and the
// SDK surface them).
func TestEngineExecuteRedactHeaders(t *testing.T) {
	secretValue := "sk_live_HEADER_ECHO_67890"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Token", "Bearer "+secretValue)
		w.Header().Set("Set-Cookie", "session="+secretValue+"; Path=/")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"data": "clean body"}`))
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		ResolveAllowlist: mockAllowlist(),
		Client:           upstream.Client(),
		ResolveSecret:    mockResolver(map[string]string{"STRIPE_KEY": secretValue}),
	}

	result, err := engine.Execute(CallRequest{
		TargetURL: upstream.URL + "/data",
		Method:    "GET",
		Injections: []Injection{
			{Style: "bearer", SecretKey: "STRIPE_KEY"},
		},
	})
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	// The clean body is untouched.
	if got := string(result.Body); !strings.Contains(got, "clean body") {
		t.Errorf("body = %q, want it to contain \"clean body\"", got)
	}

	// SECURITY: the secret value must not survive in ANY response header.
	for name, values := range result.Headers {
		for _, v := range values {
			if strings.Contains(v, secretValue) {
				t.Fatalf("SECURITY: secret VALUE leaked in response header %q: %q", name, v)
			}
		}
	}

	// Each echoing header carries the placeholder instead.
	for _, name := range []string{"X-Echo-Token", "Set-Cookie"} {
		vals := result.Headers[name]
		if len(vals) == 0 {
			t.Fatalf("expected header %q to be present in response", name)
		}
		if !strings.Contains(vals[0], RedactionPlaceholder) {
			t.Errorf("header %q = %q, want it to contain %q", name, vals[0], RedactionPlaceholder)
		}
	}
}

func TestEngineCapabilities(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		Client:           upstream.Client(),
		ResolveSecret:    mockResolver(map[string]string{"SECRET_A": "val_a", "SECRET_B": "val_b"}),
		ResolveAllowlist: mockAllowlist(),
	}

	// 1. Unrestricted agent capabilities
	_, err := engine.Execute(CallRequest{
		TargetURL:    upstream.URL,
		Method:       "GET",
		Injections:   []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
		Capabilities: nil,
	})
	if err != nil {
		t.Errorf("unrestricted agent failed: %v", err)
	}

	// 2. AllowedSecrets whitelist
	res, err := engine.Execute(CallRequest{
		TargetURL:  upstream.URL,
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_B"}},
		Capabilities: &capabilities.AgentCapabilities{
			AllowedSecrets: []string{"SECRET_A"},
		},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 for SECRET_B (not in whitelist), got %d", res.StatusCode)
	}

	// 3. DeniedSecrets blacklist
	res, err = engine.Execute(CallRequest{
		TargetURL:  upstream.URL,
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
		Capabilities: &capabilities.AgentCapabilities{
			DeniedSecrets: []string{"SECRET_A"},
		},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 for SECRET_A (in blacklist), got %d", res.StatusCode)
	}
}

type RoundTripFunc func(req *http.Request) (*http.Response, error)

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestEnginePolicies(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	upstreamHost := u.Hostname()

	engine := &Engine{
		ProjectID: "test-project",
		Client: &http.Client{
			Transport: RoundTripFunc(func(req *http.Request) (*http.Response, error) {
				target, _ := url.Parse(upstream.URL)
				req.URL.Scheme = target.Scheme
				req.URL.Host = target.Host
				transport := upstream.Client().Transport
				if transport == nil {
					transport = http.DefaultTransport
				}
				return transport.RoundTrip(req)
			}),
		},
		ResolveSecret: mockResolver(map[string]string{
			"SECRET_A": "val_a",
			"SECRET_B": "val_b",
			"SECRET_C": "val_c",
		}),
		ResolvePolicy: func(key string) (*capabilities.SecretPolicy, error) {
			if key == "SECRET_A" {
				return &capabilities.SecretPolicy{
					Domains: []string{upstreamHost},
				}, nil
			}
			if key == "SECRET_B" {
				return &capabilities.SecretPolicy{
					Domains: []string{"approved.com"},
					Methods: map[string]capabilities.Action{
						"POST": capabilities.RequestPermission,
					},
				}, nil
			}
			return nil, nil
		},
		Approvals:        NewApprovalStore(),
		ResolveAllowlist: mockAllowlist(upstreamHost, "blocked.com", "approved.com"),
	}

	// 1. Policy allow (no rules match block)
	res, err := engine.Execute(CallRequest{
		TargetURL:  upstream.URL,
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("expected 200, got %d", res.StatusCode)
	}

	// 2. Policy deny
	// Set target domain to blocked.com (by rewriting target URL or using host)
	res, err = engine.Execute(CallRequest{
		TargetURL:  "http://blocked.com/v1",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 for blocked domain, got %d", res.StatusCode)
	}

	// 3. Policy request_permission: the request is held open until a human
	// approves THIS request. ApprovalHold makes the engine wait on a channel.
	engine.ApprovalHold = 2 * time.Second

	statusCh := make(chan int, 1)
	errCh := make(chan error, 1)
	go func() {
		r, e := engine.Execute(CallRequest{
			TargetURL:  "http://approved.com/v1",
			Method:     "POST",
			Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_B"}},
			AgentID:    "agent-1",
		})
		if e != nil {
			errCh <- e
			return
		}
		statusCh <- r.StatusCode
	}()

	// The request must register as pending with a server-generated ID.
	var id string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p := engine.Approvals.PendingApprovals(); len(p) == 1 {
			id = p[0].ID
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("request never registered as pending")
	}

	// 4. Approve that one request by ID and verify it passes.
	if !engine.Approvals.ApproveByID(id) {
		t.Fatal("ApproveByID rejected a live pending request")
	}
	select {
	case e := <-errCh:
		t.Fatalf("Execute failed: %v", e)
	case status := <-statusCh:
		if status != 200 {
			t.Errorf("expected 200 after approval, got %d", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("approved request never completed")
	}

	// 5. Approvals are single-use: a second identical request is NOT covered
	// by the first approval. With a short hold it blocks then fails closed.
	engine.ApprovalHold = 50 * time.Millisecond
	res, err = engine.Execute(CallRequest{
		TargetURL:  "http://approved.com/v1",
		Method:     "POST",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_B"}},
		AgentID:    "agent-1",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 on the second request (approvals are single-use), got %d", res.StatusCode)
	}
}

func TestEngineCapabilitiesPriorityAndCaseInsensitivity(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		Client:           upstream.Client(),
		ResolveSecret:    mockResolver(map[string]string{"SECRET_A": "val_a"}),
		ResolveAllowlist: mockAllowlist(),
	}

	// 1. Blacklist priority: SECRET_A is in both allowed and denied lists. Deny should win.
	res, err := engine.Execute(CallRequest{
		TargetURL:  upstream.URL,
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
		Capabilities: &capabilities.AgentCapabilities{
			AllowedSecrets: []string{"SECRET_A"},
			DeniedSecrets:  []string{"SECRET_A"},
		},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 because blacklist takes priority, got %d", res.StatusCode)
	}

	// 2. Case insensitivity check: whitelist contains lowercase "secret_a"
	res, err = engine.Execute(CallRequest{
		TargetURL:  upstream.URL,
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
		Capabilities: &capabilities.AgentCapabilities{
			AllowedSecrets: []string{"secret_a"},
		},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("expected 200 (case-insensitive whitelist match), got %d", res.StatusCode)
	}

	// 3. Case insensitivity check: blacklist contains lowercase "secret_a"
	res, err = engine.Execute(CallRequest{
		TargetURL:  upstream.URL,
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
		Capabilities: &capabilities.AgentCapabilities{
			DeniedSecrets: []string{"secret_a"},
		},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 (case-insensitive blacklist match), got %d", res.StatusCode)
	}
}

func TestEngineAllowlistEnforcement(t *testing.T) {
	engine := &Engine{
		ProjectID:        "test-project",
		Client:           http.DefaultClient,
		ResolveSecret:    mockResolver(map[string]string{"SECRET_A": "val_a"}),
		ResolveAllowlist: mockAllowlist("allowed.com"),
	}

	// 1. Blocked domain
	res, err := engine.Execute(CallRequest{
		TargetURL:  "https://unauthorized.com/v1",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 for unauthorized domain, got %d", res.StatusCode)
	}

	// 2. Allowed domain
	// We mock the client transport to avoid actual network request
	engine.Client = &http.Client{
		Transport: RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			w := httptest.NewRecorder()
			w.WriteHeader(200)
			w.Write([]byte("allowed"))
			return w.Result(), nil
		}),
	}
	res, err = engine.Execute(CallRequest{
		TargetURL:  "https://allowed.com/v1",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("expected 200 for allowed domain, got %d", res.StatusCode)
	}
}

func TestEnginePresenceCheck(t *testing.T) {
	engine := &Engine{
		ProjectID: "test-project",
		ResolvePresence: func(key string) (bool, error) {
			if key == "KNOWN_KEY" {
				return true, nil
			}
			return false, nil
		},
		ResolveSecret: mockResolver(map[string]string{
			"KNOWN_KEY": "val",
		}),
		ResolveAllowlist: mockAllowlist("allowed.com"),
	}

	// 1. Known key - passes presence check
	engine.Client = &http.Client{
		Transport: RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			w := httptest.NewRecorder()
			w.WriteHeader(200)
			return w.Result(), nil
		}),
	}
	res, err := engine.Execute(CallRequest{
		TargetURL:  "https://allowed.com/v1",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "KNOWN_KEY"}},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("expected 200, got %d", res.StatusCode)
	}

	// 2. Unknown key - blocks immediately with error
	_, err = engine.Execute(CallRequest{
		TargetURL:  "https://allowed.com/v1",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "UNKNOWN_KEY"}},
	})
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	if !strings.Contains(err.Error(), "UNKNOWN_KEY") {
		t.Errorf("expected error message to mention key, got: %v", err)
	}
}

func TestEngineAgentWorkspaceMismatch(t *testing.T) {
	tc := NewTokenCache(5 * time.Minute)
	tc.tokens["agent-token-123"] = &CachedToken{
		TokenID:     "tok_123",
		AgentID:     "agent_id_1",
		AgentName:   "test-agent",
		WorkspaceID: "other-workspace",
		ProjectID:   "test-project",
		ValidatedAt: time.Now(),
	}

	engine := &Engine{
		ProjectID:        "test-project",
		WorkspaceID:      "my-workspace",
		TokenCache:       tc,
		ResolveSecret:    mockResolver(map[string]string{"SECRET_A": "val_a"}),
		ResolveAllowlist: mockAllowlist("allowed.com"),
	}

	res, err := engine.Execute(CallRequest{
		TargetURL:  "https://allowed.com/v1",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
		AgentToken: "agent-token-123",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 workspace mismatch, got %d", res.StatusCode)
	}
}

func TestEngineAgentProjectMismatch(t *testing.T) {
	tc := NewTokenCache(5 * time.Minute)
	tc.tokens["agent-token-123"] = &CachedToken{
		TokenID:     "tok_123",
		AgentID:     "agent_id_1",
		AgentName:   "test-agent",
		WorkspaceID: "my-workspace",
		ProjectID:   "other-project",
		ValidatedAt: time.Now(),
	}

	engine := &Engine{
		ProjectID:        "test-project",
		WorkspaceID:      "my-workspace",
		TokenCache:       tc,
		ResolveSecret:    mockResolver(map[string]string{"SECRET_A": "val_a"}),
		ResolveAllowlist: mockAllowlist("allowed.com"),
	}

	res, err := engine.Execute(CallRequest{
		TargetURL:  "https://allowed.com/v1",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
		AgentToken: "agent-token-123",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 project mismatch, got %d", res.StatusCode)
	}
}

func TestEngineAgentEnvironmentMismatch(t *testing.T) {
	tc := NewTokenCache(5 * time.Minute)
	tc.tokens["agent-token-123"] = &CachedToken{
		TokenID:     "tok_123",
		AgentID:     "agent_id_1",
		AgentName:   "test-agent",
		WorkspaceID: "my-workspace",
		ProjectID:   "test-project",
		Environment: "production",
		ValidatedAt: time.Now(),
	}

	engine := &Engine{
		ProjectID:        "test-project",
		WorkspaceID:      "my-workspace",
		TokenCache:       tc,
		ResolveSecret:    mockResolver(map[string]string{"SECRET_A": "val_a"}),
		ResolveAllowlist: mockAllowlist("allowed.com"),
	}

	res, err := engine.Execute(CallRequest{
		TargetURL:  "https://allowed.com/v1",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
		AgentToken: "agent-token-123",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("expected 403 environment mismatch, got %d", res.StatusCode)
	}
}



