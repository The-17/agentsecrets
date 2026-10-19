package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestProxyHandlerEndToEndIssue9 drives the real handleProxy path with the
// exact headers call/api_call now emit, and asserts what the upstream API
// actually received. This is the issue-#9 acceptance test: before the fix the
// upstream saw {"Channel":...} and no Content-Type.
func TestProxyHandlerEndToEndIssue9(t *testing.T) {
	type captured struct {
		body        []byte
		contentType string
		query       string
		header      string
	}

	var got captured
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.body, _ = io.ReadAll(r.Body)
		got.contentType = r.Header.Get("Content-Type")
		got.query = r.URL.Query().Get("channel")
		got.header = r.Header.Get("X-Workspace-Key")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID: "test-project",
		Client:    upstream.Client(),
		ResolveSecret: mockResolver(map[string]string{
			"SLACK_BOT_TOKEN":  "xoxb-test",
			"SLACK_CHANNEL_ID": "C0123456789",
			"WORKSPACE_KEY":    "wk-1",
		}),
		ResolveAllowlist: mockAllowlist(),
	}
	srv := &Server{Engine: engine}

	// Use the same encoder the CLI uses.
	h := http.Header{}
	applyInjections(h, []Injection{
		{Style: "bearer", SecretKey: "SLACK_BOT_TOKEN"},
		{Style: "body", Target: "channel", SecretKey: "SLACK_CHANNEL_ID"},
		{Style: "query", Target: "channel", SecretKey: "SLACK_CHANNEL_ID"},
		{Style: "header", Target: "X-Workspace-Key", SecretKey: "WORKSPACE_KEY"},
	})
	h.Set("X-AS-Target-URL", upstream.URL)
	h.Set("X-AS-Method", http.MethodPost)

	// The JSON body the operator typed. No Content-Type: the engine must
	// default it.
	req := httptest.NewRequest(http.MethodPost, "/proxy", strings.NewReader(`{"text":"hello"}`))
	req.Header = h

	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var payload map[string]string
	if err := json.Unmarshal(got.body, &payload); err != nil {
		t.Fatalf("upstream body %q is not JSON: %v", got.body, err)
	}
	if payload["channel"] != "C0123456789" {
		t.Errorf("body field %q = %q, want C0123456789 (body: %s)", "channel", payload["channel"], got.body)
	}
	if _, capitalised := payload["Channel"]; capitalised {
		t.Errorf("body gained a capitalised key: %s", got.body)
	}
	if got.contentType != "application/json" {
		t.Errorf("upstream Content-Type = %q, want application/json", got.contentType)
	}
	if got.query != "C0123456789" {
		t.Errorf("query channel = %q, want C0123456789", got.query)
	}
	if got.header != "wk-1" {
		t.Errorf("X-Workspace-Key = %q, want wk-1", got.header)
	}
}
