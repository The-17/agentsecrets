package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFetchWorkloadEnv_AcceptsRealWorkloadToken is a regression test: the client
// used to reject any token without an "agt_" prefix, but the control plane issues
// opaque `secrets.token_urlsafe(32)` values (43 chars, no prefix) and verifies
// them by hashing. The prefix check therefore broke cloud `env` for every real
// workload credential, before any request left the machine.
func TestFetchWorkloadEnv_AcceptsRealWorkloadToken(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		// Real server shape: payload nested under "data" (CustomResponse envelope).
		_, _ = w.Write([]byte(`{"status":"success","message":"Environment secrets resolved successfully","data":{"workspace_id":"ws","project_id":"p","environment":"development","secrets":{"TEST_KEY":"value"}}}`))
	}))
	defer srv.Close()

	// 43-char url-safe token, exactly like secrets.token_urlsafe(32). No "agt_".
	token := strings.Repeat("A", 43)

	secrets, err := FetchWorkloadEnv(context.Background(), srv.URL+"/api", token)
	if err != nil {
		t.Fatalf("FetchWorkloadEnv rejected a real workload token: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/workloads/env/" {
		t.Fatalf("path = %q, want /api/workloads/env/", gotPath)
	}
	if gotAuth != "Bearer "+token {
		t.Fatalf("Authorization header not forwarded verbatim")
	}
	if secrets["TEST_KEY"] != "value" {
		t.Fatalf("secrets = %v, want TEST_KEY=value", secrets)
	}
}

// TestFetchWorkloadEnv_RejectsEmptyToken guards the only remaining client-side
// precondition: a token must be present.
func TestFetchWorkloadEnv_RejectsEmptyToken(t *testing.T) {
	if _, err := FetchWorkloadEnv(context.Background(), "https://example.test/api", "  "); err == nil {
		t.Fatal("expected an error for an empty workload token")
	}
}
