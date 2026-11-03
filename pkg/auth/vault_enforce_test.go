package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/vault"
)

// TestEnforceV2VaultMigratesV1ToV2 stores a v1 vault, runs enforceV2Vault with a
// synthetic export key, and asserts the stored vault became a v2 split vault
// carrying both a password and an opaque envelope plus min_client_version.
func TestEnforceV2VaultMigratesV1ToV2(t *testing.T) {
	setupAuthTest(t)

	const (
		userID   = "enforce-user"
		email    = "enforce@example.com"
		password = "enforce-password"
	)
	_ = config.SetUserID(userID)

	privateKey := bytes.Repeat([]byte{0x07}, vault.KeySize)
	record, _, err := vault.Create(userID, password, privateKey)
	if err != nil {
		t.Fatalf("create v1 vault: %v", err)
	}

	var stored json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/auth/vault/":
			body, _ := json.Marshal(map[string]any{
				"status": "success",
				"data": map[string]any{
					"vault":         record,
					"vault_version": record.VaultVersion,
				},
			})
			w.Write(body)
		case r.Method == http.MethodPut && r.URL.Path == "/auth/vault/":
			var payload struct {
				Vault json.RawMessage `json:"vault"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			stored = payload.Vault
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": nil})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	client := api.NewClient(func() string { return "" })
	client.BaseURL = server.URL
	svc := NewService(client)

	exportKey := bytes.Repeat([]byte{0x42}, vault.KeySize)
	if err := svc.enforceV2Vault(email, password, exportKey); err != nil {
		t.Fatalf("enforceV2Vault: %v", err)
	}
	if stored == nil {
		t.Fatal("enforceV2Vault did not upload a vault")
	}

	var got vault.Vault
	if err := json.Unmarshal(stored, &got); err != nil {
		t.Fatalf("stored vault parse: %v", err)
	}
	if !got.IsSplit() {
		t.Fatalf("stored vault is not v2 (version=%d)", got.Version)
	}
	if got.MinClientVersion != vault.MinClientVersionV2 {
		t.Fatalf("min_client_version = %q, want %q", got.MinClientVersion, vault.MinClientVersionV2)
	}
	types := map[string]bool{}
	for _, env := range got.Envelopes {
		types[env.Type] = true
	}
	if !types[vault.TypePassword] || !types[vault.TypeOpaque] {
		t.Fatalf("v2 vault missing a share envelope: %v", types)
	}
	// The migrated vault must unlock with both shares to the same VK.
	if err := got.Validate(); err != nil {
		t.Fatalf("migrated vault invalid: %v", err)
	}
	vk, err := got.UnlockWithShares(userID, password, exportKey)
	if err != nil {
		t.Fatalf("migrated vault does not unlock: %v", err)
	}
	pk, err := got.PrivateKey(userID, vk)
	if err != nil || !bytes.Equal(pk, privateKey) {
		t.Fatalf("migrated vault private key mismatch: %v", err)
	}
}

// TestEnforceV2VaultNoVaultIsNoop ensures an account with no vault is left alone.
func TestEnforceV2VaultNoVaultIsNoop(t *testing.T) {
	setupAuthTest(t)
	_ = config.SetUserID("enforce-none")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/auth/vault" {
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": nil})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	client := api.NewClient(func() string { return "" })
	client.BaseURL = server.URL
	svc := NewService(client)

	if err := svc.enforceV2Vault("x@example.com", "pw", bytes.Repeat([]byte{0x01}, vault.KeySize)); err != nil {
		t.Fatalf("enforceV2Vault no-vault: %v", err)
	}
}
