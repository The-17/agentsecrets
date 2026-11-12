package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// End-to-end through the daemon wire: a mismatched X-AS-Expected-Workspace must
// fail closed (502) and never reach the upstream. This proves the CLI->daemon
// header forwarding actually enforces the assertion when a daemon is running
// (the path where a missing wire hop would otherwise silently no-op it).
func TestServerExpectedMismatchFailsClosed(t *testing.T) {
	withTempHome(t)
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	engine := &Engine{
		WorkspaceID: "ws-org",
		ProjectID:   "proj",
		Client:      upstream.Client(),
		ResolveSecret: func(key string) (string, error) {
			return "val", nil
		},
		ResolveAllowlist: func(wsID string) ([]string, error) {
			u, _ := url.Parse(upstream.URL)
			return []string{u.Hostname()}, nil
		},
	}
	srv := NewServer(0, engine)
	srv.SetSessionToken("test-session")
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/proxy", nil)
	req.Header.Set("X-AS-Session-Token", "test-session")
	req.Header.Set("X-AS-Target-URL", upstream.URL+"/v1")
	req.Header.Set("X-AS-Method", "GET")
	req.Header.Set("X-AS-Inject-Bearer", "SECRET_A")
	req.Header.Set("X-AS-Expected-Workspace", "ws-personal") // mismatch

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 502 {
		t.Fatalf("status = %d (body %q), want 502 (fail closed on context mismatch)", resp.StatusCode, string(body))
	}
	if upstreamHits != 0 {
		t.Errorf("upstream hit %d times; a mismatched call must never reach it", upstreamHits)
	}
}

// The matching direction: a correct X-AS-Expected-Workspace must pass through to
// the upstream so the assertion never becomes a deny-by-default gate.
func TestServerExpectedMatchPassesThrough(t *testing.T) {
	withTempHome(t)
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	engine := &Engine{
		WorkspaceID: "ws-org",
		ProjectID:   "proj",
		Client:      upstream.Client(),
		ResolveSecret: func(key string) (string, error) {
			return "val", nil
		},
		ResolveAllowlist: func(wsID string) ([]string, error) {
			u, _ := url.Parse(upstream.URL)
			return []string{u.Hostname()}, nil
		},
	}
	srv := NewServer(0, engine)
	srv.SetSessionToken("test-session")
	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/proxy", nil)
	req.Header.Set("X-AS-Session-Token", "test-session")
	req.Header.Set("X-AS-Target-URL", upstream.URL+"/v1")
	req.Header.Set("X-AS-Method", "GET")
	req.Header.Set("X-AS-Inject-Bearer", "SECRET_A")
	req.Header.Set("X-AS-Expected-Workspace", "ws-org")
	req.Header.Set("X-AS-Expected-Project", "proj")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d (body %q), want 200", resp.StatusCode, string(body))
	}
	if upstreamHits != 1 {
		t.Errorf("upstream hit %d times, want 1", upstreamHits)
	}
}
