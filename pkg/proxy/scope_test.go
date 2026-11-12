package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/The-17/agentsecrets/pkg/config"
)

// withTempHome points config at a fresh temp dir for the test and writes a
// GlobalConfig with a personal and a shared workspace so ResolveWorkspaceRef
// (used by AssertExpectedContext for the "personal" keyword) has real data.
func withTempHome(t *testing.T) {
	t.Helper()
	orig := config.HomeDirHook
	tmp := t.TempDir()
	globalDir := filepath.Join(tmp, ".agentsecrets")
	if err := os.MkdirAll(globalDir, 0o700); err != nil {
		t.Fatalf("mkdir global dir: %v", err)
	}
	config.HomeDirHook = func() (string, error) { return tmp, nil }
	t.Cleanup(func() { config.HomeDirHook = orig })

	cfg := &config.GlobalConfig{
		Email: "test@example.com",
		Workspaces: map[string]config.WorkspaceCacheEntry{
			"ws-personal": {Name: "go", Type: "personal"},
			"ws-org":      {Name: "acme", Type: "shared"},
		},
	}
	if err := config.SaveGlobalConfig(cfg); err != nil {
		t.Fatalf("save global config: %v", err)
	}
}

// nil Expected is a no-op (backward compatible): no assertion, no error.
func TestAssertExpectedContextNilIsNoOp(t *testing.T) {
	if err := AssertExpectedContext(nil, "ws-org", "proj", "dev"); err != nil {
		t.Fatalf("nil Expected should be a no-op, got error: %v", err)
	}
}

func TestAssertExpectedContextMatchPasses(t *testing.T) {
	withTempHome(t)
	exp := &ExpectedContext{Workspace: "ws-org", Project: "proj", Environment: "dev"}
	if err := AssertExpectedContext(exp, "ws-org", "proj", "dev"); err != nil {
		t.Fatalf("matching context should pass, got: %v", err)
	}
}

// "personal" resolves to the caller's personal workspace id, so a call bound to
// that id satisfies the assertion and a call bound to any other workspace fails
// closed. This is what makes workspace:"personal" a portable per-call address.
func TestAssertExpectedContextPersonalResolves(t *testing.T) {
	withTempHome(t)

	exp := &ExpectedContext{Workspace: "personal"}
	if err := AssertExpectedContext(exp, "ws-personal", "p", "dev"); err != nil {
		t.Fatalf("personal should resolve to ws-personal: %v", err)
	}
	if err := AssertExpectedContext(exp, "ws-org", "p", "dev"); err == nil {
		t.Fatal("personal must NOT match a non-personal workspace; expected fail-closed error")
	}
}

// A workspace named by display name (not id) resolves correctly.
func TestAssertExpectedContextWorkspaceByName(t *testing.T) {
	withTempHome(t)
	exp := &ExpectedContext{Workspace: "acme"}
	if err := AssertExpectedContext(exp, "ws-org", "p", "dev"); err != nil {
		t.Fatalf("workspace name 'acme' should resolve to ws-org: %v", err)
	}
}

// An unknown workspace reference fails closed rather than silently resolving to
// nothing (which would otherwise let a typo address the wrong context).
func TestAssertExpectedContextUnknownWorkspaceFailsClosed(t *testing.T) {
	withTempHome(t)
	exp := &ExpectedContext{Workspace: "ghost"}
	if err := AssertExpectedContext(exp, "ws-org", "p", "dev"); err == nil {
		t.Fatal("unknown workspace ref must fail closed, got nil error")
	}
}

func TestAssertExpectedContextProjectMismatchFailsClosed(t *testing.T) {
	exp := &ExpectedContext{Project: "expected-proj"}
	if err := AssertExpectedContext(exp, "ws", "other-proj", "dev"); err == nil {
		t.Fatal("project mismatch must fail closed")
	}
	if err := AssertExpectedContext(exp, "ws", "expected-proj", "dev"); err != nil {
		t.Fatalf("matching project should pass: %v", err)
	}
}

func TestAssertExpectedContextEnvironmentMismatchFailsClosed(t *testing.T) {
	exp := &ExpectedContext{Environment: "dev"}
	if err := AssertExpectedContext(exp, "ws", "p", "qa"); err == nil {
		t.Fatal("environment mismatch must fail closed")
	}
	// Environment comparison is case-insensitive by design.
	if err := AssertExpectedContext(exp, "ws", "p", "DEV"); err != nil {
		t.Fatalf("environment match (case-insensitive) should pass: %v", err)
	}
}

// The assertion is enforced where the value is injected: a mismatching Expected
// must abort the call before the upstream is ever contacted, and must surface as
// a hard error (not a 403 result carrying a secret). This is the Tier-2 guarantee.
func TestExecuteCtxExpectedMismatchFailsClosed(t *testing.T) {
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
			return []string{"example.com"}, nil
		},
	}

	res, err := engine.Execute(CallRequest{
		TargetURL:  "https://example.com/v1",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
		// Declare a workspace the call is NOT bound to.
		Expected: &ExpectedContext{Workspace: "ws-personal"},
	})
	if err == nil {
		t.Fatalf("expected a fail-closed error on context mismatch, got result: %+v", res)
	}
	if upstreamHits != 0 {
		t.Errorf("upstream was hit %d times; a mismatched call must never reach it", upstreamHits)
	}
}

// A matching Expected passes through to the upstream (the assertion must not
// become a deny-by-default gate for legitimate calls).
func TestExecuteCtxExpectedMatchPassesThrough(t *testing.T) {
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

	res, err := engine.Execute(CallRequest{
		TargetURL:  upstream.URL + "/v1",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
		Expected:   &ExpectedContext{Workspace: "ws-org", Project: "proj"},
	})
	if err != nil {
		t.Fatalf("matching Expected should pass through, got error: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("status = %d, want 200", res.StatusCode)
	}
	if upstreamHits != 1 {
		t.Errorf("upstream hit %d times, want 1", upstreamHits)
	}
}
