package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchWorkloadIdentity_RoundTrip(t *testing.T) {
	var gotAuth, gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(WorkloadIdentity{
			IdentityLevel:  "issued",
			WorkspaceID:    "ws_1",
			ProjectID:      "proj_1",
			Environment:    "production",
			TokenID:        "tok_1",
			AgentID:        "agent_1",
			Scopes:         []string{"secrets:env", "secrets:proxy"},
			AgentScopes:    []string{"secrets:env", "secrets:proxy", "secrets:read"},
			Attenuated:     []string{"secrets:read"},
			AllowedDomains: []string{"api.stripe.com"},
			CanDo:          []string{"Deliver environment secrets", "Make upstream calls"},
		})
	}))
	defer srv.Close()

	id, err := FetchWorkloadIdentity(context.Background(), srv.URL, "agt_secret_token_value")
	if err != nil {
		t.Fatalf("FetchWorkloadIdentity: %v", err)
	}
	if gotAuth != "Bearer agt_secret_token_value" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/identity" {
		t.Errorf("request = %s %s, want POST /v1/identity", gotMethod, gotPath)
	}
	if id.WorkspaceID != "ws_1" || id.ProjectID != "proj_1" || id.Environment != "production" {
		t.Errorf("binding = %+v", id)
	}
	if len(id.Scopes) != 2 || id.CanDo[0] != "Deliver environment secrets" {
		t.Errorf("scopes/can_do = %v / %v", id.Scopes, id.CanDo)
	}
	if len(id.Attenuated) != 1 || id.Attenuated[0] != "secrets:read" {
		t.Errorf("attenuated = %v", id.Attenuated)
	}
}

func TestFetchWorkloadIdentity_RefusesRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://169.254.169.254/latest/meta-data/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	_, err := FetchWorkloadIdentity(context.Background(), srv.URL, "tok")
	if err == nil || !strings.Contains(err.Error(), "refusing to follow") {
		t.Fatalf("redirect error = %v, want refusal", err)
	}
}

func TestFetchWorkloadIdentity_ErrorStatuses(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   string
	}{
		{http.StatusUnauthorized, `{"message":"token revoked"}`, "token revoked"},
		{http.StatusForbidden, `{"detail":"expired"}`, "expired"},
		{http.StatusInternalServerError, `{"message":"boom"}`, "500"},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		_, err := FetchWorkloadIdentity(context.Background(), srv.URL, "tok")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("status %d error = %v, want substring %q", tc.status, err, tc.want)
		}
		srv.Close()
	}
}

func TestFetchWorkloadIdentity_EmptyToken(t *testing.T) {
	if _, err := FetchWorkloadIdentity(context.Background(), "https://resolver.example", ""); err == nil {
		t.Fatal("empty token must fail before any network call")
	}
}

func TestFetchWorkloadIdentity_OversizedBodyRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxIdentityResponseBytes+1)))
	}))
	defer srv.Close()

	_, err := FetchWorkloadIdentity(context.Background(), srv.URL, "tok")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized error = %v, want size refusal", err)
	}
}
