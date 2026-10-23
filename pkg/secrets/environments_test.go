package secrets

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
)

// TestRemoteEnvironments_ReadsControlPlaneInventory covers the reason this call
// exists: the local cache only knows names this machine has touched, so a custom
// environment created on the dashboard was invisible to `environment list`,
// completion, and every multi-environment command.
func TestRemoteEnvironments_ReadsControlPlaneInventory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/projects/prj-1/environments/" {
			t.Errorf("path = %q, want /projects/prj-1/environments/", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"project_id":"prj-1","environments":[
			{"name":"development","is_standard":true,"secret_count":3},
			{"name":"staging","is_standard":true,"secret_count":1},
			{"name":"production","is_standard":true,"secret_count":0},
			{"name":"preview-pr-12","is_standard":false,"secret_count":2}
		],"counts":{}}}`))
	}))
	defer srv.Close()

	svc := NewService(api.NewClientWithURL(srv.URL, func() string { return "token" }))
	got := svc.RemoteEnvironments("prj-1")

	want := []string{"development", "staging", "production", "preview-pr-12"}
	if len(got) != len(want) {
		t.Fatalf("environments = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("environments = %v, want %v", got, want)
		}
	}
}

// TestRemoteEnvironments_FailsQuietly proves the offline path is unchanged: a
// server that cannot answer yields nil, and Environments falls back to the local
// list rather than failing the command.
func TestRemoteEnvironments_FailsQuietly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	svc := NewService(api.NewClientWithURL(srv.URL, func() string { return "token" }))
	if got := svc.RemoteEnvironments("prj-1"); got != nil {
		t.Fatalf("environments = %v, want nil on server failure", got)
	}
}

// TestEnvironments_PrefersServerOverLocalCache proves a custom environment
// created on the dashboard is visible to every CLI surface even though this
// machine has never selected it. LocalEnvironments alone would miss it, which is
// exactly the bug this call fixes.
func TestEnvironments_PrefersServerOverLocalCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"environments":[
			{"name":"development","is_standard":true,"secret_count":1},
			{"name":"staging","is_standard":true,"secret_count":0},
			{"name":"production","is_standard":true,"secret_count":0},
			{"name":"preview-pr-12","is_standard":false,"secret_count":4}
		]}}`))
	}))
	defer srv.Close()

	svc := NewService(api.NewClientWithURL(srv.URL, func() string { return "token" }))
	// An empty project root stands in for a machine with no local trace at all.
	got, err := svc.Environments("prj-1", "")
	if err != nil {
		t.Fatalf("Environments: %v", err)
	}
	if len(got) != 4 || got[3] != "preview-pr-12" {
		t.Fatalf("environments = %v, want the server inventory including preview-pr-12", got)
	}
}

// TestRemoteEnvironments_SkipsInvalidNames proves the inventory cannot smuggle a
// name past the slug rule. The control plane validates on write, so this only
// guards against a stale or foreign row.
func TestRemoteEnvironments_SkipsInvalidNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"environments":[
			{"name":"qa","is_standard":false,"secret_count":1},
			{"name":"has space","is_standard":false,"secret_count":1}
		]}}`))
	}))
	defer srv.Close()

	svc := NewService(api.NewClientWithURL(srv.URL, func() string { return "token" }))
	got := svc.RemoteEnvironments("prj-1")
	if len(got) != 1 || got[0] != "qa" {
		t.Fatalf("environments = %v, want [qa]", got)
	}
}
