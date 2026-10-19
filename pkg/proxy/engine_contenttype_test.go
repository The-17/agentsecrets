package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// newContentTypeEngine runs one call against a capture server and returns the
// Content-Type the upstream actually received.
func contentTypeForCall(t *testing.T, headers map[string]string, body string) string {
	t.Helper()

	var seen string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		Client:           upstream.Client(),
		ResolveSecret:    mockResolver(map[string]string{"KEY": "value"}),
		ResolveAllowlist: mockAllowlist(),
	}

	var raw []byte
	if body != "" {
		raw = []byte(body)
	}
	result, err := engine.Execute(CallRequest{
		TargetURL:  upstream.URL,
		Method:     "POST",
		Headers:    headers,
		Body:       raw,
		Injections: []Injection{{Style: "bearer", SecretKey: "KEY"}},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", result.StatusCode)
	}
	return seen
}

// TestEngineDefaultsJSONContentType is the second half of issue #9: a plain
// JSON --body used to reach the upstream untyped, so JSON APIs rejected it.
func TestEngineDefaultsJSONContentType(t *testing.T) {
	got := contentTypeForCall(t, nil, `{"channel":"C0123456789","text":"test"}`)
	if got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
}

// TestEngineKeepsCallerContentType proves the default never overrides an
// explicit header, which is what --set-header exists for.
func TestEngineKeepsCallerContentType(t *testing.T) {
	got := contentTypeForCall(t,
		map[string]string{"Content-Type": "application/x-ndjson"},
		`{"channel":"C0123456789"}`,
	)
	if got != "application/x-ndjson" {
		t.Errorf("Content-Type = %q, want application/x-ndjson", got)
	}
}

// TestEngineLeavesNonJSONBodyUntyped keeps the guess honest: a body that is not
// JSON gets no invented Content-Type.
func TestEngineLeavesNonJSONBodyUntyped(t *testing.T) {
	got := contentTypeForCall(t, nil, "plain text, not json")
	if got != "" {
		t.Errorf("Content-Type = %q, want empty", got)
	}
}
