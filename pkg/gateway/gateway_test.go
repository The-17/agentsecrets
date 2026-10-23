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

	"github.com/The-17/agentsecrets/pkg/proxy"
)

// isolateEnv clears every variable this package reads, so a developer's shell
// cannot decide a test outcome.
func isolateEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{envUseCloud, envMode, envToken, envTokenFile, envResolver, envServerURL} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
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

func TestResolverURL(t *testing.T) {
	isolateEnv(t)
	if got := ResolverURL(); got != DefaultResolverURL {
		t.Errorf("default = %q, want %q", got, DefaultResolverURL)
	}

	t.Setenv(envResolver, "https://resolver.internal/")
	if got := ResolverURL(); got != "https://resolver.internal" {
		t.Errorf("override = %q, want the trailing slash trimmed", got)
	}

	t.Setenv(envResolver, "")
	t.Setenv(envServerURL, "https://self.example/api")
	if got := ResolverURL(); got != "https://self.example" {
		t.Errorf("derived = %q, want the /api suffix stripped", got)
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
	t.Setenv(envResolver, srv.URL)
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
	t.Setenv(envResolver, srv.URL)
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
	})
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

// TestSecretsForEnvCloudFetchesWorkloadEnv verifies the cloud env path.
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
	t.Setenv(envResolver, srv.URL)

	got, err := SecretsForEnv(Selection{Mode: ModeLocal}, func() (map[string]string, error) {
		return map[string]string{"LOCAL": "yes"}, nil
	})
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

func TestSecretsForEnvCloudFetchesWorkloadEnv(t *testing.T) {
	isolateEnv(t)
	t.Setenv(envToken, "workload-token")
	t.Setenv(envServerURL, "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/workloads/env/" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer workload-token" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"data":{"secrets":{"DATABASE_URL":"postgres://x"}}}`))
	}))
	defer srv.Close()
	t.Setenv(envServerURL, srv.URL)

	got, err := SecretsForEnv(Selection{Mode: ModeCloud}, nil)
	if err != nil {
		t.Fatalf("SecretsForEnv: %v", err)
	}
	if got["DATABASE_URL"] != "postgres://x" {
		t.Errorf("got %v", got)
	}
}
