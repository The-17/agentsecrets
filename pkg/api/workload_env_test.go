package api

import (
	"context"
	"encoding/json"
	"io"
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

	secrets, err := FetchWorkloadEnv(context.Background(), srv.URL+"/api", token, "")
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
	if _, err := FetchWorkloadEnv(context.Background(), "https://example.test/api", "  ", ""); err == nil {
		t.Fatal("expected an error for an empty workload token")
	}
}

// TestFetchWorkloadEnv_SendsCustomEnvironment covers the custom-environment
// path: the control plane reads the environment from the JSON body, so a cloud
// `env --env qa` has to send one. Sending nothing keeps the token's binding.
func TestFetchWorkloadEnv_SendsCustomEnvironment(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"environment":"qa","secrets":{}}}`))
	}))
	defer srv.Close()

	if _, err := FetchWorkloadEnv(context.Background(), srv.URL+"/api", "token", "qa"); err != nil {
		t.Fatalf("FetchWorkloadEnv: %v", err)
	}
	var body map[string]string
	if err := json.Unmarshal(gotBody, &body); err != nil {
		t.Fatalf("body %q is not JSON: %v", gotBody, err)
	}
	if body["env"] != "qa" {
		t.Fatalf(`body env = %q, want "qa"`, body["env"])
	}
}

// TestFetchWorkloadEnv_OmitsEnvironmentWhenUnset proves the default path is
// unchanged: no body field, so the server falls back to the token's binding.
func TestFetchWorkloadEnv_OmitsEnvironmentWhenUnset(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"secrets":{}}}`))
	}))
	defer srv.Close()

	if _, err := FetchWorkloadEnv(context.Background(), srv.URL+"/api", "token", ""); err != nil {
		t.Fatalf("FetchWorkloadEnv: %v", err)
	}
	if len(gotBody) != 0 {
		t.Fatalf("body = %q, want empty so the token binding applies", gotBody)
	}
}

// TestFetchWorkloadEnv_SurfacesServerReason proves a refusal keeps the server's
// own words. A bare "status 403" tells a developer nothing about why their
// custom environment did not resolve.
func TestFetchWorkloadEnv_SurfacesServerReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"Workload token lacks can_env_read capability"}`))
	}))
	defer srv.Close()

	_, err := FetchWorkloadEnv(context.Background(), srv.URL+"/api", "token", "qa")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "lacks can_env_read") {
		t.Fatalf("error %q dropped the server reason", err)
	}
}
