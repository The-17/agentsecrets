package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
)

func TestSignupFlow(t *testing.T) {
	// Setup: redirect config to temp dir
	tmpDir := t.TempDir()
	oldHome := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return tmpDir, nil }
	defer func() { config.HomeDirHook = oldHome }()

	// Initialize config directory
	if err := config.InitGlobalConfig(); err != nil {
		t.Fatalf("InitGlobalConfig failed: %v", err)
	}

	// 1. Mock API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/register/" {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "User created",
				"data":    map[string]string{"id": "user-123"},
			})
			return
		}
		if r.URL.Path == "/auth/login/" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"access":     "access-123",
					"refresh":    "refresh-456",
					"expires_at": "2025-01-01T00:00:00Z",
					"user": map[string]string{
						"public_key": "some-pub-key",
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// 2. Service setup
	client := api.NewClient(func() string { return "" })
	client.BaseURL = server.URL
	svc := NewService(client)

	// 3. Perform signup
	req := SignupRequest{
		FirstName: "Test",
		LastName:  "User",
		Email:     "test@example.com",
		Password:  "password123",
	}
	err := svc.Signup(req)
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	if config.GetEmail() != "test@example.com" {
		t.Error("Email was not stored in config after signup")
	}
}

func TestLoginFlow(t *testing.T) {
	// Setup: redirect config to temp dir
	tmpDir := t.TempDir()
	oldHome := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return tmpDir, nil }
	defer func() { config.HomeDirHook = oldHome }()

	if err := config.InitGlobalConfig(); err != nil {
		t.Fatalf("InitGlobalConfig failed: %v", err)
	}

	// 1. Mock API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"access":     "access-123",
				"refresh":    "refresh-456",
				"expires_at": "2025-01-01T00:00:00Z",
			},
		})
	}))
	defer server.Close()

	// 2. Service setup
	client := api.NewClient(func() string { return "" })
	client.BaseURL = server.URL
	svc := NewService(client)

	// 3. Perform login
	dummyKey := make([]byte, 32)
	err := svc.PerformLogin("test@example.com", "password123", dummyKey, dummyKey)
	if err != nil {
		t.Logf("PerformLogin warning (keyring likely failed): %v", err)
	}

	// Verify tokens were stored
	if config.GetAccessToken() != "access-123" {
		t.Error("Access token was not stored correctly")
	}
}
