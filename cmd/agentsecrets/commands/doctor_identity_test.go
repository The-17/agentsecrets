package commands

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/keychainauth"
)

func identityEnv(t *testing.T, mode, token string) {
	t.Helper()
	t.Setenv("AGENTSECRETS_MODE", mode)
	t.Setenv("AGENTSECRETS_USE_CLOUD", "")
	t.Setenv("AGENTSECRETS_TOKEN", token)
	t.Setenv("AGENTSECRETS_TOKEN_FILE", "")
	t.Setenv("AS_AGENT_TOKEN", "")
	t.Setenv("AGENTSECRETS_AGENT_TOKEN", "")
	t.Setenv("AGENTSECRETS_AGENT_TOKEN_FILE", "")
}

func TestCollectDoctorIdentity_CloudSuccess(t *testing.T) {
	identityEnv(t, "cloud", "agt_test_token")
	called := false
	fetch := func(_ context.Context, _, tok string) (*api.WorkloadIdentity, error) {
		called = true
		if tok != "agt_test_token" {
			t.Errorf("fetch got token %q", tok)
		}
		return &api.WorkloadIdentity{
			IdentityLevel: "issued",
			WorkspaceID:   "ws_1",
			ProjectID:     "proj_1",
			Environment:   "production",
			TokenID:       "tok_1",
			AgentID:       "agent_reader",
			Scopes:        []string{"secrets:env", "secrets:proxy"},
			AgentScopes:   []string{"secrets:env", "secrets:proxy", "secrets:read"},
			Attenuated:    []string{"secrets:read"},
			CanDo:         []string{"Deliver environment secrets"},
		}, nil
	}

	id := collectDoctorIdentity(fetch)
	if !called {
		t.Fatal("resolver was not queried in cloud mode with a token")
	}
	if !id.ResolverReached || !id.TokenPresent {
		t.Fatalf("identity = %+v, want reached + token present", id)
	}
	if id.Mode != "cloud" || id.TokenSource != "AGENTSECRETS_TOKEN" {
		t.Errorf("mode/source = %s/%s", id.Mode, id.TokenSource)
	}
	if id.WorkspaceID != "ws_1" || id.Environment != "production" || id.AgentID != "agent_reader" {
		t.Errorf("binding = %+v", id)
	}
	if len(id.Scopes) != 2 || len(id.Attenuated) != 1 {
		t.Errorf("scopes/attenuated = %v/%v", id.Scopes, id.Attenuated)
	}
	if id.UnavailableReason != "" {
		t.Errorf("unexpected unavailable reason: %s", id.UnavailableReason)
	}
}

func TestCollectDoctorIdentity_ResolverOutageDegrades(t *testing.T) {
	identityEnv(t, "cloud", "agt_test_token")
	fetch := func(_ context.Context, _, _ string) (*api.WorkloadIdentity, error) {
		return nil, errors.New("network unreachable")
	}

	id := collectDoctorIdentity(fetch)
	if id.ResolverReached {
		t.Fatal("must not report resolver reached on failure")
	}
	if id.Mode != "cloud" || !id.TokenPresent {
		t.Errorf("local facts lost on outage: %+v", id)
	}
	if id.UnavailableReason == "" {
		t.Fatal("outage must be recorded as a reason, not swallowed")
	}

	// The warning must not mark the installation unhealthy.
	report := &keychainauth.Report{}
	appendIdentityFinding(report, id)
	if !report.Healthy() {
		t.Fatal("resolver outage marked the whole doctor report unhealthy")
	}
	if len(report.Findings) != 1 || report.Findings[0].Status != keychainauth.StatusWarn {
		t.Errorf("findings = %+v, want one warning", report.Findings)
	}
}

func TestCollectDoctorIdentity_CloudNoTokenSkipsNetwork(t *testing.T) {
	identityEnv(t, "cloud", "")
	fetch := func(_ context.Context, _, _ string) (*api.WorkloadIdentity, error) {
		t.Fatal("resolver must not be called without a token")
		return nil, nil
	}

	id := collectDoctorIdentity(fetch)
	if id.TokenPresent || id.ResolverReached {
		t.Errorf("identity = %+v", id)
	}
	if id.UnavailableReason == "" {
		t.Fatal("missing token must be explained")
	}
}

// Full chain: doctor's collection + the REAL api.FetchWorkloadIdentity client
// against a mock resolver. Proves the wire shape both repos actually agree on,
// not just a stubbed fetch.
func TestCollectDoctorIdentity_RealClientAgainstMockResolver(t *testing.T) {
	identityEnv(t, "cloud", "agt_integration_token")
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"identity_level":"issued","workspace_id":"ws_int","project_id":"proj_int",
			"workspace_wide":false,"environment":"staging","token_id":"tok_int",
			"agent_id":"agent_int","scopes":["secrets:env"],
			"agent_scopes":["secrets:env","secrets:admin"],
			"attenuated":["secrets:admin"],"allowed_domains":["api.example.com"],
			"can_do":["Deliver environment secrets"]
		}`))
	}))
	defer srv.Close()

	fetch := func(ctx context.Context, _, tok string) (*api.WorkloadIdentity, error) {
		return api.FetchWorkloadIdentity(ctx, srv.URL, tok)
	}
	id := collectDoctorIdentity(fetch)
	if !id.ResolverReached {
		t.Fatalf("real client did not reach resolver: %+v", id)
	}
	if gotPath != "/v1/identity" || gotAuth != "Bearer agt_integration_token" {
		t.Errorf("request = %s %q", gotPath, gotAuth)
	}
	if id.WorkspaceID != "ws_int" || id.Environment != "staging" || id.TokenID != "tok_int" {
		t.Errorf("binding = %+v", id)
	}
	if len(id.Scopes) != 1 || id.Scopes[0] != "secrets:env" || len(id.Attenuated) != 1 {
		t.Errorf("scopes/attenuated = %v/%v", id.Scopes, id.Attenuated)
	}
	if len(id.CanDo) != 1 {
		t.Errorf("can_do = %v", id.CanDo)
	}
}

func TestCollectDoctorIdentity_LocalModeSkipsNetwork(t *testing.T) {
	identityEnv(t, "local", "")
	fetch := func(_ context.Context, _, _ string) (*api.WorkloadIdentity, error) {
		t.Fatal("resolver must not be called in local mode")
		return nil, nil
	}

	id := collectDoctorIdentity(fetch)
	if id.Mode != "local" || id.ResolverReached {
		t.Errorf("identity = %+v", id)
	}
	if id.UnavailableReason == "" {
		t.Fatal("local mode must explain why no cloud identity is shown")
	}
}
