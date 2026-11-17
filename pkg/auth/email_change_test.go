package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/vault"
)

// TestChangeEmailWithOpaqueRotatesV2Shares drives an OPAQUE-enrolled account
// with a v2 split-share vault through a real control-plane-shaped mock and the
// real OPAQUE sidecar. Changing the email rotates the credential id and therefore
// the export key. The old share must be re-wrapped under the new key, or the next
// passwordless login cannot reconstruct the Vault Key and only the recovery key
// could get the account back.
func TestChangeEmailWithOpaqueRotatesV2Shares(t *testing.T) {
	setupAuthTest(t)
	sidecar := startSidecar(t)

	const (
		userID   = "email-change-user"
		oldEmail = "email-change-old@example.com"
		newEmail = "email-change-new@example.com"
		password = "email-change-password"
		otp      = 123456
	)
	_ = config.SetUserID(userID)
	_ = config.SetEmail(oldEmail)
	_ = config.SetOpaqueEnrolled(false)

	var storedRecord string
	var storedVault json.RawMessage
	var vaultVersion int
	var putExpectedVersion int
	var putCallCount int
	var confirmCallCount int

	mux := http.NewServeMux()
	forward := func(w http.ResponseWriter, r *http.Request, sidecarPath string, injectRecord bool) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		if injectRecord {
			body["record"] = storedRecord
		}
		buf, _ := json.Marshal(body)
		req, _ := http.NewRequest(r.Method, sidecar+sidecarPath, bytes.NewReader(buf))
		req.Header.Set("Authorization", "Bearer e2e-token")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		if sidecarPath == "/v1/register/finish" {
			var parsed map[string]any
			if json.Unmarshal(out, &parsed) == nil {
				if s, ok := parsed["record"].(string); ok {
					storedRecord = s
				}
			}
		}
		env, _ := json.Marshal(map[string]any{"status": "success", "data": json.RawMessage(out)})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(env)
	}
	mux.HandleFunc("/auth/opaque/register/start/", func(w http.ResponseWriter, r *http.Request) {
		forward(w, r, "/v1/register/response", false)
	})
	mux.HandleFunc("/auth/opaque/register/finish/", func(w http.ResponseWriter, r *http.Request) {
		forward(w, r, "/v1/register/finish", false)
	})
	mux.HandleFunc("/auth/opaque/login/start/", func(w http.ResponseWriter, r *http.Request) {
		forward(w, r, "/v1/login/start", true)
	})
	mux.HandleFunc("/auth/opaque/login/finish/", func(w http.ResponseWriter, r *http.Request) {
		// Export-key derivation discards the returned tokens. An empty success
		// envelope is enough; the key was already computed client-side from KE2.
		env, _ := json.Marshal(map[string]any{"status": "success", "data": map[string]any{}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(env)
	})
	mux.HandleFunc("/auth/capabilities/", func(w http.ResponseWriter, r *http.Request) {
		env, _ := json.Marshal(map[string]any{"status": "success", "data": map[string]any{"opaque": true}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(env)
	})
	mux.HandleFunc("/auth/update-email/confirm/", func(w http.ResponseWriter, r *http.Request) {
		confirmCallCount++
		env, _ := json.Marshal(map[string]any{"status": "success", "data": nil})
		w.Header().Set("Content-Type", "application/json")
		w.Write(env)
	})
	mux.HandleFunc("/auth/vault/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			data := map[string]any{"vault": storedVault, "vault_version": vaultVersion}
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": data})
		case http.MethodPut:
			var payload struct {
				ExpectedVersion int             `json:"expected_version"`
				Vault           json.RawMessage `json:"vault"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			putExpectedVersion = payload.ExpectedVersion
			storedVault = payload.Vault
			putCallCount++
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": nil})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := api.NewClient(func() string { return "test-token" })
	client.BaseURL = server.URL
	svc := NewService(client)

	// Enroll under the OLD email first. No vault exists yet, so enforceV2Vault
	// is a no-op and the returned export key is the genuine sidecar value.
	oldExportKey, err := svc.EnrollOpaque(oldEmail, password)
	if err != nil {
		t.Fatalf("enroll old email: %v", err)
	}
	if len(oldExportKey) == 0 {
		t.Fatal("enrollment returned no export key")
	}

	// Deriving the export key before any swap must reproduce the enrollment key.
	derivedOld, err := svc.DeriveOpaqueExportKey(oldEmail, password)
	if err != nil {
		t.Fatalf("derive old export key: %v", err)
	}
	if !bytes.Equal(derivedOld, oldExportKey) {
		t.Fatal("pre-swap derivation did not reproduce the enrollment export key")
	}

	// Wrap a v2 split vault under that real export key.
	privateKey := bytes.Repeat([]byte{0x7B}, vault.KeySize)
	v, material, err := vault.CreateSplit(userID, password, oldExportKey, privateKey)
	if err != nil {
		t.Fatalf("CreateSplit: %v", err)
	}
	storedVault, _ = json.Marshal(v)
	vaultVersion = v.VaultVersion

	// Change the email. This must capture the old key before the swap, re-enroll
	// under the new address, and re-wrap the vault share under the new key.
	if err := svc.ChangeEmailWithOpaque(newEmail, otp, password); err != nil {
		t.Fatalf("ChangeEmailWithOpaque: %v", err)
	}
	if confirmCallCount != 1 {
		t.Fatalf("confirm endpoint called %d times, want 1", confirmCallCount)
	}
	if putCallCount != 1 {
		t.Fatalf("vault PUT called %d times, want 1", putCallCount)
	}
	if putExpectedVersion != vaultVersion {
		t.Fatalf("vault PUT expected_version = %d, want %d", putExpectedVersion, vaultVersion)
	}

	var rotated vault.Vault
	if err := json.Unmarshal(storedVault, &rotated); err != nil {
		t.Fatalf("parse rotated vault: %v", err)
	}
	if !rotated.IsSplit() {
		t.Fatal("vault was downgraded from v2")
	}
	if err := rotated.Validate(); err != nil {
		t.Fatalf("rotated vault invalid: %v", err)
	}
	if rotated.VaultVersion != vaultVersion+1 {
		t.Fatalf("rotated vault version = %d, want %d", rotated.VaultVersion, vaultVersion+1)
	}
	if _, err := rotated.UnlockWithShares(userID, password, oldExportKey); err == nil {
		t.Error("rotated vault still opens with the OLD export key")
	}

	// A fresh login under the new email reproduces the new export key. It must
	// open the rotated vault to the same Vault Key and private key.
	newExportKey, err := svc.DeriveOpaqueExportKey(newEmail, password)
	if err != nil {
		t.Fatalf("derive new export key: %v", err)
	}
	rotatedVK, err := rotated.UnlockWithShares(userID, password, newExportKey)
	if err != nil {
		t.Fatalf("rotated vault did not open with new export key: %v", err)
	}
	if !bytes.Equal(rotatedVK, material.VK) {
		t.Error("rotated vault unlocked to a different Vault Key")
	}
	rotatedPK, err := rotated.PrivateKey(userID, rotatedVK)
	if err != nil || !bytes.Equal(rotatedPK, privateKey) {
		t.Fatalf("rotated private key mismatch: %v", err)
	}
}

// TestChangeEmailWithoutOpaqueJustConfirms verifies the non-enrolled branch
// does not touch the vault or derivation path.
func TestChangeEmailWithoutOpaqueJustConfirms(t *testing.T) {
	setupAuthTest(t)
	const (
		userID   = "email-change-plain-user"
		oldEmail = "email-change-plain-old@example.com"
		newEmail = "email-change-plain-new@example.com"
	)
	_ = config.SetUserID(userID)
	_ = config.SetEmail(oldEmail)
	_ = config.SetOpaqueEnrolled(false)

	confirmCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/auth/update-email/confirm/" {
			confirmCalls++
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": nil})
			return
		}
		// Any OPAQUE or vault call is a failure in this branch.
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	client := api.NewClient(func() string { return "test-token" })
	client.BaseURL = server.URL
	svc := NewService(client)

	if err := svc.ChangeEmailWithOpaque(newEmail, 654321, "unused-password"); err != nil {
		t.Fatalf("ChangeEmailWithOpaque (non-enrolled): %v", err)
	}
	if confirmCalls != 1 {
		t.Fatalf("confirm endpoint called %d times, want 1", confirmCalls)
	}
}
