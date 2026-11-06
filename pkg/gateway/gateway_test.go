package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/proxy"
)

// isolateEnv clears every variable this package reads, so a developer's shell
// cannot decide a test outcome. It also redirects the global config to a fresh
// temp dir, because Select reads the persisted default mode (agentsecrets mode
// cloud|local) BEFORE the workload-token branch. Without this, any machine that
// has run `agentsecrets mode` (including the CI/VM images used for the v4
// runbook) leaves a stored mode in place, the token branch is never reached, and
// the precedence tests fail with a misleading "config" source.
func isolateEnv(t *testing.T) {
	t.Helper()
	oldHome := config.HomeDirHook
	tmp := t.TempDir()
	config.HomeDirHook = func() (string, error) { return tmp, nil }
	t.Cleanup(func() { config.HomeDirHook = oldHome })
	for _, k := range []string{envUseCloud, envMode, envToken, envTokenFile, envServerURL, config.ProjectDirEnv,
		"AS_AGENT_TOKEN", "AGENTSECRETS_AGENT_TOKEN", "AGENTSECRETS_AGENT_TOKEN_FILE"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	config.InvalidateProjectCache()
	t.Cleanup(config.InvalidateProjectCache)
	oldResolver := resolverBaseURL
	resolverBaseURL = DefaultResolverURL
	t.Cleanup(func() { resolverBaseURL = oldResolver })
}

// useProjectMode pins project resolution to a temporary project carrying the
// given mode. An empty mode writes no mode key, which models a project that has
// not made a choice.
func useProjectMode(t *testing.T, mode string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".agentsecrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"project_id":"p-1"}`
	if mode != "" {
		body = `{"project_id":"p-1","mode":"` + mode + `"}`
	}
	if err := os.WriteFile(filepath.Join(dir, ".agentsecrets", "project.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.ProjectDirEnv, dir)
	config.InvalidateProjectCache()
	t.Cleanup(config.InvalidateProjectCache)
}

// useTestResolver points Resolve at a local httptest server. It is the only
// supported way to change the resolver host, and it is available to tests in
// this package only, never to a user through configuration.
func useTestResolver(t *testing.T, url string) {
	t.Helper()
	old := resolverBaseURL
	resolverBaseURL = url
	t.Cleanup(func() { resolverBaseURL = old })
}

func TestSelectPrecedence(t *testing.T) {
	isolateEnv(t)

	t.Run("default is local", func(t *testing.T) {
		sel, err := Select("")
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if sel.Mode != ModeLocal {
			t.Errorf("mode = %q, want local", sel.Mode)
		}
		if sel.Source != "default" {
			t.Errorf("source = %q, want default", sel.Source)
		}
	})

	t.Run("flag beats env", func(t *testing.T) {
		t.Setenv(envMode, "cloud")
		sel, err := Select("local")
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if sel.Mode != ModeLocal || sel.Source != "flag" {
			t.Errorf("got %q/%q, want local/flag", sel.Mode, sel.Source)
		}
	})

	t.Run("explicit local beats a token in the environment", func(t *testing.T) {
		t.Setenv(envToken, "workload-token")
		sel, err := Select("local")
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if sel.Mode != ModeLocal {
			t.Errorf("mode = %q, want local: a token must not override an explicit local choice", sel.Mode)
		}
	})

	t.Run("token alone selects cloud", func(t *testing.T) {
		t.Setenv(envToken, "workload-token")
		sel, err := Select("")
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if sel.Mode != ModeCloud {
			t.Errorf("mode = %q, want cloud", sel.Mode)
		}
	})

	t.Run("token file selects cloud", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(path, []byte("file-token\n"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(envTokenFile, path)
		sel, err := Select("")
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if sel.Mode != ModeCloud {
			t.Errorf("mode = %q, want cloud", sel.Mode)
		}
		if got := TokenFromEnv(); got != "file-token" {
			t.Errorf("token = %q, want the trimmed file contents", got)
		}
	})

	t.Run("alias token alone does not auto-select cloud", func(t *testing.T) {
		// 'agent register' tells users to export AS_AGENT_TOKEN. That name is
		// also a standing local-attribution variable for the proxy, so it must
		// not silently pick cloud the way AGENTSECRETS_TOKEN does; the user
		// chooses cloud explicitly (mode cloud / AGENTSECRETS_USE_CLOUD).
		t.Setenv("AS_AGENT_TOKEN", "agent-token")
		sel, err := Select("")
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if sel.Mode != ModeLocal {
			t.Errorf("mode = %q, want local: the AS_AGENT_TOKEN alias must not auto-select cloud", sel.Mode)
		}
	})

	t.Run("invalid flag is rejected", func(t *testing.T) {
		if _, err := Select("hybrid"); err == nil {
			t.Fatal("expected an error for an unknown mode")
		}
	})

	t.Run("invalid env mode is rejected", func(t *testing.T) {
		t.Setenv(envMode, "hybrid")
		if _, err := Select(""); err == nil {
			t.Fatal("expected an error for an invalid AGENTSECRETS_MODE")
		}
	})
}

// TestSelectProjectMode pins the project-level override. A project mode is a
// persisted choice for that project only: it outranks the global preference and
// the token fallback, but a flag or an env var still wins so a container can
// override a checked-in choice without editing the repo.
func TestSelectProjectMode(t *testing.T) {
	t.Run("project mode outranks global mode", func(t *testing.T) {
		isolateEnv(t)
		if err := config.SetDefaultMode("local"); err != nil {
			t.Fatal(err)
		}
		useProjectMode(t, "cloud")
		sel, err := Select("")
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if sel.Mode != ModeCloud || sel.Source != "project config" {
			t.Errorf("got %q/%q, want cloud/project config", sel.Mode, sel.Source)
		}
	})

	t.Run("project mode outranks a token", func(t *testing.T) {
		isolateEnv(t)
		useProjectMode(t, "local")
		t.Setenv(envToken, "workload-token")
		sel, err := Select("")
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if sel.Mode != ModeLocal || sel.Source != "project config" {
			t.Errorf("got %q/%q, want local/project config", sel.Mode, sel.Source)
		}
	})

	t.Run("env mode outranks project mode", func(t *testing.T) {
		isolateEnv(t)
		useProjectMode(t, "local")
		t.Setenv(envMode, "cloud")
		sel, err := Select("")
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if sel.Mode != ModeCloud || sel.Source != envMode {
			t.Errorf("got %q/%q, want cloud/%s", sel.Mode, sel.Source, envMode)
		}
	})

	t.Run("flag outranks project mode", func(t *testing.T) {
		isolateEnv(t)
		useProjectMode(t, "cloud")
		sel, err := Select("local")
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if sel.Mode != ModeLocal || sel.Source != "flag" {
			t.Errorf("got %q/%q, want local/flag", sel.Mode, sel.Source)
		}
	})

	t.Run("unset project mode falls through", func(t *testing.T) {
		isolateEnv(t)
		useProjectMode(t, "")
		sel, err := Select("")
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if sel.Mode != ModeLocal || sel.Source != "default" {
			t.Errorf("got %q/%q, want local/default", sel.Mode, sel.Source)
		}
	})

	t.Run("corrupt project mode is ignored", func(t *testing.T) {
		isolateEnv(t)
		useProjectMode(t, "hybrid")
		sel, err := Select("")
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if sel.Mode != ModeLocal {
			t.Errorf("mode = %q, want local: a corrupt project mode must not reach the router", sel.Mode)
		}
	})
}

// TestTokenFromEnv locks the workload-token lookup the CLI documents in its own
// errors: canonical names first, then legacy aliases, matching the MCP bridge's
// workload-credential chain.
func TestTokenFromEnv(t *testing.T) {
	isolateEnv(t)

	t.Run("AS_AGENT_TOKEN alias is read", func(t *testing.T) {
		t.Setenv("AS_AGENT_TOKEN", "register-told-me")
		if got := TokenFromEnv(); got != "register-told-me" {
			t.Errorf("token = %q, want the alias read", got)
		}
	})

	t.Run("AGENTSECRETS_AGENT_TOKEN alias is read", func(t *testing.T) {
		t.Setenv("AGENTSECRETS_AGENT_TOKEN", "agent-alt")
		if got := TokenFromEnv(); got != "agent-alt" {
			t.Errorf("token = %q, want the alias read", got)
		}
	})

	t.Run("AGENTSECRETS_AGENT_TOKEN_FILE is read", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "agent-token")
		if err := os.WriteFile(path, []byte("agent-file-token\n"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AGENTSECRETS_AGENT_TOKEN_FILE", path)
		if got := TokenFromEnv(); got != "agent-file-token" {
			t.Errorf("token = %q, want the trimmed file contents", got)
		}
	})

	t.Run("CANONICAL AGENTSECRETS_TOKEN outranks the aliases", func(t *testing.T) {
		t.Setenv(envToken, "canonical")
		t.Setenv("AS_AGENT_TOKEN", "alias")
		t.Setenv("AGENTSECRETS_AGENT_TOKEN", "alt")
		if got := TokenFromEnv(); got != "canonical" {
			t.Errorf("token = %q, want the canonical name to win", got)
		}
	})

	t.Run("AGENTSECRETS_TOKEN_FILE outranks the aliases", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(path, []byte("canonical-file\n"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(envTokenFile, path)
		t.Setenv("AS_AGENT_TOKEN", "alias")
		if got := TokenFromEnv(); got != "canonical-file" {
			t.Errorf("token = %q, want the canonical file to win", got)
		}
	})

	t.Run("empty everywhere means empty", func(t *testing.T) {
		if got := TokenFromEnv(); got != "" {
			t.Errorf("token = %q, want empty", got)
		}
	})
}

func TestResolverURL(t *testing.T) {
	isolateEnv(t)
	if got := ResolverURL(); got != DefaultResolverURL {
		t.Errorf("default = %q, want %q", got, DefaultResolverURL)
	}

	// There is exactly one resolver. The removed env override must not be read,
	// even when it is present in the process environment.
	t.Setenv("AGENTSECRETS_CLOUD_RESOLVER_URL", "https://resolver.internal/")
	if got := ResolverURL(); got != DefaultResolverURL {
		t.Errorf("env override moved the resolver to %q; it must stay on %q", got, DefaultResolverURL)
	}

	// A self-hosted control plane must never move resolution off the official
	// cloud resolver. Setting the control-plane URL used to derive a resolver
	// host from it, which let a self-hosted deployment escape billing.
	t.Setenv(envServerURL, "https://self.example/api")
	if got := ResolverURL(); got != DefaultResolverURL {
		t.Errorf("self-hosted control plane moved the resolver to %q; it must stay on %q", got, DefaultResolverURL)
	}
}

// TestCallCloudSendsHandlesAndNeverPlaintext is the security property that
// matters: the cloud request carries key names, never values.
func TestCallCloudSendsHandlesAndNeverPlaintext(t *testing.T) {
	isolateEnv(t)

	var got resolveRequest
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("decoding request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status_code":200,"headers":{"Content-Type":"application/json"},"body":"{\"ok\":true}","redacted":false}`))
	}))
	defer srv.Close()
	useTestResolver(t, srv.URL)
	t.Setenv(envToken, "workload-token")

	res, err := Call(CallRequest{
		TargetURL: "https://api.stripe.com/v1/charges",
		Method:    "POST",
		Body:      []byte(`{"amount":1000}`),
		Injections: []proxy.Injection{
			{Style: "bearer", SecretKey: "STRIPE_KEY"},
			{Style: "body", Target: "meta.key", SecretKey: "OTHER_KEY"},
		},
	}, Selection{Mode: ModeCloud})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if auth != "Bearer workload-token" {
		t.Errorf("authorization = %q", auth)
	}
	if got.Headers["Authorization"] != "Bearer {{STRIPE_KEY}}" {
		t.Errorf("authorization header = %q, want the handle", got.Headers["Authorization"])
	}
	if !strings.Contains(got.Body, `"{{OTHER_KEY}}"`) {
		t.Errorf("body = %q, want the nested handle", got.Body)
	}
	if !strings.Contains(got.Body, "1000") {
		t.Errorf("body = %q, want the original field preserved", got.Body)
	}
	if res.StatusCode != 200 || string(res.Body) != `{"ok":true}` {
		t.Errorf("result = %+v", res)
	}
	if res.Via != ModeCloud {
		t.Errorf("via = %q, want cloud", res.Via)
	}
}

func TestCallCloudRejectsStylesItCannotExpress(t *testing.T) {
	isolateEnv(t)
	t.Setenv(envToken, "tok")

	for _, inj := range []proxy.Injection{
		{Style: "basic", SecretKey: "K"},
		{Style: "query", Target: "api_key", SecretKey: "K"},
	} {
		_, err := Call(CallRequest{
			TargetURL:  "https://api.example.com/x",
			Method:     "GET",
			Injections: []proxy.Injection{inj},
		}, Selection{Mode: ModeCloud})
		if err == nil {
			t.Fatalf("style %q: expected an error, got nil", inj.Style)
		}
		if !strings.Contains(err.Error(), "--local") {
			t.Errorf("style %q: error should name the local fallback, got %v", inj.Style, err)
		}
	}
}

func TestCallCloudWithoutTokenFailsActionably(t *testing.T) {
	isolateEnv(t)
	_, err := Call(CallRequest{TargetURL: "https://api.example.com", Method: "GET"}, Selection{Mode: ModeCloud})
	if err == nil {
		t.Fatal("expected an error without a token")
	}
	if !strings.Contains(err.Error(), "AGENTSECRETS_TOKEN") {
		t.Errorf("error should name the missing variable, got %v", err)
	}
}

func TestCallCloudSurfacesResolverErrors(t *testing.T) {
	isolateEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error_code":"domain_blocked","message":"Target host 'evil.example' is not permitted by workspace allowlist"}`))
	}))
	defer srv.Close()
	useTestResolver(t, srv.URL)
	t.Setenv(envToken, "tok")

	_, err := Call(CallRequest{TargetURL: "https://evil.example/x", Method: "GET"}, Selection{Mode: ModeCloud})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "domain_blocked") || !strings.Contains(err.Error(), "allowlist") {
		t.Errorf("error lost the resolver's reason: %v", err)
	}
}

// TestSecretsForEnvLocalUsesCallback proves the router delegates rather than
// reimplementing local resolution, so local enforcement cannot be bypassed.
func TestSecretsForEnvLocalUsesCallback(t *testing.T) {
	isolateEnv(t)
	called := false
	got, err := SecretsForEnv(Selection{Mode: ModeLocal}, func() (map[string]string, error) {
		called = true
		return map[string]string{"A": "1"}, nil
	}, "")
	if err != nil {
		t.Fatalf("SecretsForEnv: %v", err)
	}
	if !called {
		t.Fatal("local callback was not used")
	}
	if got["A"] != "1" {
		t.Errorf("got %v", got)
	}
}

// TestLocalModeNeverCallsTheResolver proves the router's local branch cannot
// reach the cloud: with a resolver listening and a token set, a local selection
// must still use the local callback only.
func TestLocalModeNeverCallsTheResolver(t *testing.T) {
	isolateEnv(t)
	t.Setenv(envToken, "workload-token")

	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	useTestResolver(t, srv.URL)

	got, err := SecretsForEnv(Selection{Mode: ModeLocal}, func() (map[string]string, error) {
		return map[string]string{"LOCAL": "yes"}, nil
	}, "")
	if err != nil {
		t.Fatalf("SecretsForEnv: %v", err)
	}
	if hit {
		t.Fatal("local mode contacted the cloud resolver")
	}
	if got["LOCAL"] != "yes" {
		t.Errorf("got %v, want the local callback result", got)
	}
}

// TestSecretsForEnvCloudFetchesWorkloadEnv verifies the cloud env path,
// including that a named environment is forwarded rather than dropped.
func TestSecretsForEnvCloudFetchesWorkloadEnv(t *testing.T) {
	isolateEnv(t)
	t.Setenv(envToken, "workload-token")
	t.Setenv(envServerURL, "")

	var gotEnv string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/workloads/env/" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer workload-token" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		var payload struct {
			Env string `json:"env"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		gotEnv = payload.Env
		_, _ = w.Write([]byte(`{"data":{"secrets":{"DATABASE_URL":"postgres://x"}}}`))
	}))
	defer srv.Close()
	t.Setenv(envServerURL, srv.URL)

	got, err := SecretsForEnv(Selection{Mode: ModeCloud}, nil, "qa")
	if err != nil {
		t.Fatalf("SecretsForEnv: %v", err)
	}
	if got["DATABASE_URL"] != "postgres://x" {
		t.Errorf("got %v", got)
	}
	if gotEnv != "qa" {
		t.Errorf("environment = %q, want qa forwarded to the workload endpoint", gotEnv)
	}
}
