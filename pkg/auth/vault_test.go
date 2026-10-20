package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/keychainauth"
	"github.com/The-17/agentsecrets/pkg/vault"
)

func setupAuthTest(t *testing.T) {
	t.Helper()
	tmpDir := t.TempDir()
	oldHome := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return tmpDir, nil }
	t.Cleanup(func() { config.HomeDirHook = oldHome })
	keychainauth.SetupTestStub()
	t.Cleanup(keychainauth.TeardownTestStub)
	if err := config.InitGlobalConfig(); err != nil {
		t.Fatalf("InitGlobalConfig: %v", err)
	}
}

func TestLoginUnlocksVaultAndPinsProofKey(t *testing.T) {
	setupAuthTest(t)
	const (
		password = "password123"
		userID   = "user-123"
	)
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/login/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
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
	}))
	defer server.Close()

	client := api.NewClient(func() string { return config.GetAccessToken() })
	client.BaseURL = server.URL
	svc := NewService(client)

	result, err := svc.PerformLogin("test@example.com", password, nil, nil)
	if err != nil {
		t.Fatalf("PerformLogin: %v", err)
	}
	if result.VaultCreated {
		t.Fatal("existing vault reported as created")
	}
	if result.VaultVersion != v.VaultVersion {
		t.Fatalf("vault version %d, want %d", result.VaultVersion, v.VaultVersion)
	}
	if config.GetVaultPubKey() != v.VaultPubKey {
		t.Fatal("vault proof key was not pinned")
	}
	if config.GetUserID() != userID {
		t.Fatalf("user id %q, want %q", config.GetUserID(), userID)
	}
}

func TestLoginMigratesLegacyAccount(t *testing.T) {
	setupAuthTest(t)
	const (
		password = "password123"
		userID   = "user-123"
	)
	privateKey, publicKey, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, salt, err := crypto.EncryptPrivateKey(privateKey, password)
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu      sync.Mutex
		putBody map[string]interface{}
		putAuth string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/login/":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"access":                "access-123",
					"refresh":               "refresh-456",
					"expires_at":            "2025-01-01T00:00:00Z",
					"encrypted_private_key": encrypted,
					"key_salt":              salt,
					"user": map[string]interface{}{
						"id":         userID,
						"public_key": base64.StdEncoding.EncodeToString(publicKey),
					},
				},
			})
		case r.URL.Path == "/auth/vault/" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"vault": nil, "vault_version": 0},
			})
		case r.URL.Path == "/auth/vault/" && r.Method == http.MethodPut:
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			putBody = body
			putAuth = r.Header.Get("Authorization")
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := api.NewClient(func() string { return config.GetAccessToken() })
	client.BaseURL = server.URL
	svc := NewService(client)

	result, err := svc.PerformLogin("test@example.com", password, nil, nil)
	if err != nil {
		t.Fatalf("PerformLogin: %v", err)
	}
	if !result.VaultCreated {
		t.Fatal("legacy account was not migrated")
	}
	if result.RecoveryKey == "" {
		t.Fatal("migration did not return a recovery key")
	}
	if result.VaultVersion != 1 {
		t.Fatalf("vault version %d, want 1", result.VaultVersion)
	}

	mu.Lock()
	body := putBody
	auth := putAuth
	mu.Unlock()
	if body == nil {
		t.Fatal("vault was not uploaded")
	}
	if auth != "Bearer access-123" {
		t.Fatalf("vault upload auth header %q", auth)
	}
	if body["expected_version"].(float64) != 0 {
		t.Fatalf("expected_version %v, want 0", body["expected_version"])
	}
	raw, err := json.Marshal(body["vault"])
	if err != nil {
		t.Fatal(err)
	}
	var stored vault.Vault
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if err := stored.Validate(); err != nil {
		t.Fatalf("uploaded vault invalid: %v", err)
	}
	if len(stored.Envelopes) != 2 {
		t.Fatalf("uploaded vault has %d envelopes, want 2", len(stored.Envelopes))
	}
	vk, err := stored.UnlockWithRecoveryKey(userID, result.RecoveryKey)
	if err != nil {
		t.Fatalf("uploaded vault recovery key does not unlock: %v", err)
	}
	recovered, err := stored.PrivateKey(userID, vk)
	if err != nil || !bytes.Equal(recovered, privateKey) {
		t.Fatalf("uploaded vault private key mismatch: %v", err)
	}
	if config.GetVaultPubKey() != stored.VaultPubKey {
		t.Fatal("migrated vault proof key was not pinned")
	}
}

func TestLoginOldServerSkipsVault(t *testing.T) {
	setupAuthTest(t)
	const password = "password123"
	privateKey, publicKey, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, salt, err := crypto.EncryptPrivateKey(privateKey, password)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/login/":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"access":                "access-123",
					"refresh":               "refresh-456",
					"expires_at":            "2025-01-01T00:00:00Z",
					"encrypted_private_key": encrypted,
					"key_salt":              salt,
					"user": map[string]interface{}{
						"id":         "user-123",
						"public_key": base64.StdEncoding.EncodeToString(publicKey),
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := api.NewClient(func() string { return config.GetAccessToken() })
	client.BaseURL = server.URL
	svc := NewService(client)

	result, err := svc.PerformLogin("test@example.com", password, nil, nil)
	if err != nil {
		t.Fatalf("PerformLogin: %v", err)
	}
	if result.VaultCreated || result.RecoveryKey != "" {
		t.Fatal("old server unexpectedly produced a vault")
	}
	if len(result.Warnings) == 0 || !strings.Contains(result.Warnings[0], "does not support vault") {
		t.Fatalf("missing rollout warning: %#v", result.Warnings)
	}
}

func TestChangePasswordRewrapsVaultAndLegacyBlob(t *testing.T) {
	setupAuthTest(t)
	const (
		oldPassword = "password123"
		newPassword = "newpassword123"
		userID      = "user-123"
	)
	privateKey, publicKey, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	v, _, err := vault.Create(userID, oldPassword, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	rawVault, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu        sync.Mutex
		patchBody map[string]interface{}
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/login/":
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
		case r.URL.Path == "/auth/vault/" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"vault":         json.RawMessage(rawVault),
					"vault_version": v.VaultVersion,
				},
			})
		case r.URL.Path == "/auth/change-password/" && r.Method == http.MethodPatch:
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			patchBody = body
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := api.NewClient(func() string { return config.GetAccessToken() })
	client.BaseURL = server.URL
	svc := NewService(client)

	if _, err := svc.PerformLogin("test@example.com", oldPassword, nil, nil); err != nil {
		t.Fatalf("PerformLogin: %v", err)
	}
	if err := svc.ChangePassword(oldPassword, newPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	mu.Lock()
	body := patchBody
	mu.Unlock()
	if body == nil {
		t.Fatal("change-password request was not sent")
	}
	if body["expected_version"].(float64) != 1 {
		t.Fatalf("expected_version %v, want 1", body["expected_version"])
	}
	raw, err := json.Marshal(body["vault"])
	if err != nil {
		t.Fatal(err)
	}
	var updated vault.Vault
	if err := json.Unmarshal(raw, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.VaultVersion != 2 {
		t.Fatalf("vault version %d, want 2", updated.VaultVersion)
	}
	if err := updated.Validate(); err != nil {
		t.Fatalf("updated vault invalid: %v", err)
	}
	if _, err := updated.UnlockWithPassword(userID, oldPassword); err == nil {
		t.Fatal("old password still unlocks the vault")
	}
	vk, err := updated.UnlockWithPassword(userID, newPassword)
	if err != nil {
		t.Fatalf("new password does not unlock the vault: %v", err)
	}
	if _, err := updated.PrivateKey(userID, vk); err != nil {
		t.Fatalf("updated vault private key: %v", err)
	}

	encrypted := body["encrypted_private_key"].(string)
	salt := body["key_salt"].(string)
	legacyKey, err := crypto.DecryptPrivateKey(encrypted, newPassword, salt)
	if err != nil {
		t.Fatalf("new legacy blob: %v", err)
	}
	if !bytes.Equal(legacyKey, privateKey) {
		t.Fatal("legacy blob does not contain the account private key")
	}
}
