package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
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
		ProjectID:     "test-project",
		Client:        upstream.Client(),
		ResolveSecret: mockResolver(map[string]string{"STRIPE_KEY": "sk_test_123"}),
		SkipAllowlist: true,
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
		SkipAllowlist: true,
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
		ProjectID:     "test-project",
		Client:        upstream.Client(),
		ResolveSecret: mockResolver(map[string]string{"GMAP_KEY": "gmap-key-123"}),
		SkipAllowlist: true,
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
		ProjectID:     "test-project",
		Client:        http.DefaultClient,
		ResolveSecret: mockResolver(map[string]string{}), // no secrets
		SkipAllowlist: true,
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
		ProjectID:     "test-project",
		Client:        http.DefaultClient,
		ResolveSecret: mockResolver(map[string]string{}),
		SkipAllowlist: true,
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
		ProjectID:     "test-project",
		Client:        http.DefaultClient,
		ResolveSecret: mockResolver(map[string]string{}),
		SkipAllowlist: true,
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
		ProjectID:     "test-project",
		Client:        upstream.Client(),
		ResolveSecret: mockResolver(map[string]string{"KEY": "val"}),
		SkipAllowlist: true,
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
		ProjectID:     "test-project",
		Client:        upstream.Client(),
		Audit:         audit,
		ResolveSecret: mockResolver(map[string]string{"STRIPE_KEY": secretValue}),
		SkipAllowlist: true,
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
		ProjectID:     "test-project",
		SkipAllowlist: true,
		Client:        upstream.Client(),
		ResolveSecret: mockResolver(map[string]string{"STRIPE_KEY": secretValue}),
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
