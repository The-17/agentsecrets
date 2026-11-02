package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestEngineNoInjectionAllowsHeaderOrBody pins LOC-012: a request with no
// credential injection is still valid when it carries a literal header or a
// body. Only a genuinely empty request (no injection, no header, no body) is
// refused. Before the fix, any request with zero injections was rejected, which
// broke literal POSTs and header-only calls the runbook exercises.
func TestEngineNoInjectionAllowsHeaderOrBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		Client:           upstream.Client(),
		ResolveSecret:    mockResolver(map[string]string{}),
		ResolveAllowlist: mockAllowlist(),
	}

	// Truly empty: no injection, no header, no body -> refused.
	if _, err := engine.Execute(CallRequest{TargetURL: upstream.URL + "/x", Method: "GET"}); err == nil || !strings.Contains(err.Error(), "at least one of") {
		t.Fatalf("empty call: err = %v, want an 'at least one of' refusal", err)
	}

	// No injection but a literal header -> allowed.
	res, err := engine.Execute(CallRequest{
		TargetURL: upstream.URL + "/x",
		Method:    "GET",
		Headers:   map[string]string{"X-Plain": "v"},
	})
	if err != nil {
		t.Fatalf("header-only call was refused: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("header-only StatusCode = %d, want 200", res.StatusCode)
	}

	// No injection but a body -> allowed.
	res, err = engine.Execute(CallRequest{
		TargetURL: upstream.URL + "/x",
		Method:    "POST",
		Body:      []byte(`{"a":1}`),
	})
	if err != nil {
		t.Fatalf("body-only call was refused: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("body-only StatusCode = %d, want 200", res.StatusCode)
	}
}
