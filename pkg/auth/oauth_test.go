package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keychainauth"
)

func setupOAuthConfig(t *testing.T) {
	t.Helper()
	tmpDir := t.TempDir()
	oldHome := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return tmpDir, nil }
	t.Cleanup(func() { config.HomeDirHook = oldHome })
	keychainauth.SetupTestStub()
	t.Cleanup(keychainauth.TeardownTestStub)
	if err := config.InitGlobalConfig(); err != nil {
		t.Fatalf("InitGlobalConfig failed: %v", err)
	}
}

func TestOAuthLoginRejectsUnknownProvider(t *testing.T) {
	setupOAuthConfig(t)
	svc := NewService(api.NewClient(func() string { return "" }))
	if _, err := svc.OAuthLogin("myspace"); err == nil {
		t.Fatal("expected an error for an unsupported provider")
	}
}

func TestOAuthLoginFailsClosedWhenProviderDisabled(t *testing.T) {
	setupOAuthConfig(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "This sign-in provider is not available."})
	}))
	defer server.Close()

	client := api.NewClient(func() string { return "" })
	client.BaseURL = server.URL
	if _, err := NewService(client).OAuthLogin("google"); err == nil {
		t.Fatal("expected an error when the provider is disabled")
	}
}

func TestOAuthLoginHappyPathStoresSession(t *testing.T) {
	setupOAuthConfig(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/authorize/"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "success",
				"data": map[string]string{
					"authorize_url": "https://accounts.example/consent",
					"state":         "st-123",
				},
			})
		case strings.HasSuffix(r.URL.Path, "/exchange/"):
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["code"] != "code-abc" || body["state"] != "st-123" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "bad code"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"access":     "access-abc",
					"refresh":    "refresh-abc",
					"expires_at": "2027-01-01T00:00:00Z",
					"user": map[string]string{
						"id":    "user-1",
						"email": "social@example.com",
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Simulate the browser: hit the loopback callback with the code and state.
	oldOpen := openBrowser
	openBrowser = func(url string) error {
		go func() {
			resp, err := http.Get(oauthRedirectURI + "?code=code-abc&state=st-123")
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
	t.Cleanup(func() { openBrowser = oldOpen })

	client := api.NewClient(func() string { return "" })
	client.BaseURL = server.URL
	result, err := NewService(client).OAuthLogin("google")
	if err != nil {
		t.Fatalf("OAuthLogin failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected a result")
	}
	if got := config.GetEmail(); got != "social@example.com" {
		t.Fatalf("email not stored, got %q", got)
	}
	if got := config.GetAccessToken(); got != "access-abc" {
		t.Fatalf("access token not stored, got %q", got)
	}
	if len(result.Warnings) == 0 {
		t.Fatal("expected a warning that the vault stays locked without a password")
	}
}

func TestOAuthLoginRejectsStateMismatch(t *testing.T) {
	setupOAuthConfig(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/authorize/") {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]string{
					"authorize_url": "https://accounts.example/consent",
					"state":         "st-123",
				},
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	oldOpen := openBrowser
	openBrowser = func(url string) error {
		go func() {
			resp, err := http.Get(oauthRedirectURI + "?code=code-abc&state=WRONG")
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
	t.Cleanup(func() { openBrowser = oldOpen })

	client := api.NewClient(func() string { return "" })
	client.BaseURL = server.URL
	if _, err := NewService(client).OAuthLogin("github"); err == nil {
		t.Fatal("expected an error on state mismatch")
	}
}
