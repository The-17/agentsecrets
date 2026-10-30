package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/The-17/agentsecrets/pkg/capabilities"
)

// A policy that cannot be read must block the call. Treating an unreadable
// policy as "no policy" (the old behavior: `policy, _ := e.ResolvePolicy(...)`)
// silently disabled enforcement whenever the resolver failed, which is exactly
// the window an attacker wants.
func TestPolicyResolverErrorFailsClosed(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID: "test-project",
		Client:    upstream.Client(),
		ResolveSecret: mockResolver(map[string]string{
			"SECRET_A": "val_a",
		}),
		ResolvePolicy: func(key string) (*capabilities.SecretPolicy, error) {
			return nil, errors.New("keychain unreadable")
		},
		ResolveAllowlist: mockAllowlist("example.com"),
	}

	res, err := engine.Execute(CallRequest{
		TargetURL:  "https://example.com/v1",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
	})
	if err != nil {
		t.Fatalf("Execute returned an error, want a blocked 403 result: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("status = %d, want 403 (fail closed)", res.StatusCode)
	}
	var blocked struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(res.Body, &blocked); err != nil {
		t.Fatalf("blocked body %q is not JSON: %v", res.Body, err)
	}
	if blocked.Error != "policy_unavailable" {
		t.Errorf("blocked error = %q, want policy_unavailable", blocked.Error)
	}
	if upstreamHits != 0 {
		t.Errorf("upstream was hit %d times; a blocked call must never reach it", upstreamHits)
	}
}

// Each secret's policy is evaluated against the request. One denied secret in
// the injection list blocks the whole call: partial injection would leak the
// allowed secrets alongside a use the policy forbids.
func TestPerSecretPolicyDenyBlocksWholeCall(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID: "test-project",
		Client:    upstream.Client(),
		ResolveSecret: mockResolver(map[string]string{
			"SECRET_A": "val_a",
			"SECRET_B": "val_b",
		}),
		ResolvePolicy: func(key string) (*capabilities.SecretPolicy, error) {
			if key == "SECRET_B" {
				return &capabilities.SecretPolicy{
					Domains: []string{"other.com"}, // upstream not in it → Deny
				}, nil
			}
			return nil, nil
		},
		ResolveAllowlist: mockAllowlist("example.com"),
	}

	res, err := engine.Execute(CallRequest{
		TargetURL: "https://example.com/v1",
		Method:    "GET",
		Injections: []Injection{
			{Style: "bearer", SecretKey: "SECRET_A"},
			{Style: "header", Target: "X-B", SecretKey: "SECRET_B"},
		},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("status = %d, want 403 (SECRET_B policy denies example.com)", res.StatusCode)
	}
	var blocked struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(res.Body, &blocked); err != nil {
		t.Fatalf("blocked body %q is not JSON: %v", res.Body, err)
	}
	if blocked.Error != "policy_denied" {
		t.Errorf("blocked error = %q, want policy_denied", blocked.Error)
	}
	if upstreamHits != 0 {
		t.Errorf("upstream was hit %d times; a denied call must never reach it", upstreamHits)
	}
}

// The positive direction: with every injected secret's policy satisfied, the
// call goes through and both secrets are enforced only by their own policies.
func TestPerSecretPoliciesAllowWhenSatisfied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	upstreamHost := u.Hostname()

	engine := &Engine{
		ProjectID: "test-project",
		Client:    upstream.Client(),
		ResolveSecret: mockResolver(map[string]string{
			"SECRET_A": "val_a",
			"SECRET_B": "val_b",
		}),
		ResolvePolicy: func(key string) (*capabilities.SecretPolicy, error) {
			switch key {
			case "SECRET_A":
				// Scoped: only the upstream host, GET only.
				return &capabilities.SecretPolicy{
					Rules: []capabilities.PolicyRule{{
						Domain:  upstreamHost,
						Methods: map[string]capabilities.Action{"GET": capabilities.Allow},
					}},
				}, nil
			default:
				return nil, nil
			}
		},
		ResolveAllowlist: mockAllowlist(upstreamHost, "other.com"),
	}

	res, err := engine.Execute(CallRequest{
		TargetURL: upstream.URL + "/v1",
		Method:    "GET",
		Injections: []Injection{
			{Style: "bearer", SecretKey: "SECRET_A"},
			{Style: "header", Target: "X-B", SecretKey: "SECRET_B"},
		},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("status = %d, want 200 (all policies satisfied)", res.StatusCode)
	}

	// The same scoped secret to a different domain is denied even though the
	// workspace allowlist covers it: the secret's own policy is tighter.
	res, err = engine.Execute(CallRequest{
		TargetURL:  "https://other.com/v1",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "SECRET_A"}},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if res.StatusCode != 403 {
		t.Errorf("status = %d, want 403 (scoped secret outside its rule domains)", res.StatusCode)
	}
}
