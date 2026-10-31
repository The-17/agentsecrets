package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/vault"
)

// socialTestServer serves the two endpoints a social onboarding touches:
// /auth/keys/initialize/ (new account) and /auth/login/ (both cases).
func socialTestServer(t *testing.T, password string) (*httptest.Server, *int32, *map[string]any) {
	t.Helper()
	const userID = "user-social"
	privateKey, publicKey, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	v, _, err := vault.Create(userID, password, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	rawVault, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	var initCalls int32
	captured := map[string]any{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/keys/initialize/":
			atomic.AddInt32(&initCalls, 1)
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			for k, val := range body {
				captured[k] = val
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{}})
		case "/auth/login/":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"access":        "access-123",
					"refresh":       "refresh-456",
					"expires_at":    "2025-01-01T00:00:00Z",
					"vault":         json.RawMessage(rawVault),
					"vault_version": v.VaultVersion,
					"user": map[string]interface{}{
						"id":         userID,
						"public_key": base64.StdEncoding.EncodeToString(publicKey),
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return server, &initCalls, &captured
}

func TestCompleteSocialOnboarding_NewAccountInitializesKeys(t *testing.T) {
	setupAuthTest(t)
	const password = "password123"
	server, initCalls, captured := socialTestServer(t, password)
	defer server.Close()

	client := api.NewClient(func() string { return config.GetAccessToken() })
	client.BaseURL = server.URL
	svc := NewService(client)

	result, err := svc.CompleteSocialOnboarding("social@example.com", password, false)
	if err != nil {
		t.Fatalf("CompleteSocialOnboarding: %v", err)
	}
	if !result.HasKeys {
		t.Error("result.HasKeys = false, want true after onboarding")
	}
	if atomic.LoadInt32(initCalls) != 1 {
		t.Fatalf("keys/initialize called %d times, want 1", *initCalls)
	}
	for _, field := range []string{"public_key", "encrypted_private_key", "key_salt", "password"} {
		if _, ok := (*captured)[field]; !ok {
			t.Errorf("keys/initialize body missing %q", field)
		}
	}
	if (*captured)["password"] != password {
		t.Error("keys/initialize did not carry the chosen password")
	}
}

func TestCompleteSocialOnboarding_ExistingAccountSkipsKeySetup(t *testing.T) {
	setupAuthTest(t)
	const password = "password123"
	server, initCalls, _ := socialTestServer(t, password)
	defer server.Close()

	client := api.NewClient(func() string { return config.GetAccessToken() })
	client.BaseURL = server.URL
	svc := NewService(client)

	if _, err := svc.CompleteSocialOnboarding("social@example.com", password, true); err != nil {
		t.Fatalf("CompleteSocialOnboarding: %v", err)
	}
	if atomic.LoadInt32(initCalls) != 0 {
		t.Fatalf("keys/initialize called %d times for an account that already has keys, want 0", *initCalls)
	}
}

func TestCompleteSocialOnboarding_RejectsShortPassword(t *testing.T) {
	setupAuthTest(t)
	svc := NewService(api.NewClient(func() string { return "" }))
	if _, err := svc.CompleteSocialOnboarding("social@example.com", "short", false); err == nil {
		t.Fatal("short password was accepted")
	}
}
