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

// TestRecoverAccountRewrapsV2Shares drives a full recovery of a v2 split-share
// vault through a mock control plane and the real OPAQUE sidecar. After recovery
// re-enrolls OPAQUE (which rotates the export key), the OPAQUE share must be
// re-wrapped under the new export key, the vault must remain v2 (never
// downgraded), and the recovery key must still unlock it.
func TestRecoverAccountRewrapsV2Shares(t *testing.T) {
	setupAuthTest(t)
	sidecar := startSidecar(t)

	const (
		userID     = "recover-v2-user"
		email      = "recover-v2@example.com"
		oldPassword = "old-password"
		newPassword = "new-recovered-password"
	)
	_ = config.SetUserID(userID)

	privateKey := bytes.Repeat([]byte{0xAB}, vault.KeySize)
	exportKey := bytes.Repeat([]byte{0xCD}, vault.KeySize)
	recVault, material, err := vault.CreateSplit(userID, oldPassword, exportKey, privateKey)
	if err != nil {
		t.Fatalf("CreateSplit: %v", err)
	}
	recoveryKey := vault.EncodeRecoveryKey(material.RecoveryKey)

	// Server-side OPAQUE record captured from enrollment (unused here: recovery
	// clears it and re-enrolls, which produces a fresh one via the sidecar).

	var stored json.RawMessage
	serveVault := func() json.RawMessage {
		if stored != nil {
			return stored
		}
		b, _ := json.Marshal(recVault)
		return b
	}

	mux := http.NewServeMux()
	forward := func(w http.ResponseWriter, r *http.Request, sidecarPath string) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		body["credential_id"] = email
		buf, _ := json.Marshal(body)
		req, _ := http.NewRequest(r.Method, sidecar+sidecarPath, bytes.NewReader(buf))
		req.Header.Set("Authorization", "Bearer e2e-token")
		req.Header.Set("Content-Type", "application/json")
		resp, ferr := http.DefaultClient.Do(req)
		if ferr != nil {
			http.Error(w, ferr.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		env, _ := json.Marshal(map[string]any{"status": "success", "data": json.RawMessage(out)})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(env)
	}
	mux.HandleFunc("/auth/opaque/register/start/", func(w http.ResponseWriter, r *http.Request) {
		forward(w, r, "/v1/register/response")
	})
	mux.HandleFunc("/auth/opaque/register/finish/", func(w http.ResponseWriter, r *http.Request) {
		forward(w, r, "/v1/register/finish")
	})
	mux.HandleFunc("/auth/opaque/login/start/", func(w http.ResponseWriter, r *http.Request) {
		forward(w, r, "/v1/login/start")
	})
	mux.HandleFunc("/auth/opaque/login/finish/", func(w http.ResponseWriter, r *http.Request) {
		forward(w, r, "/v1/login/finish")
	})
	mux.HandleFunc("/auth/capabilities/", func(w http.ResponseWriter, r *http.Request) {
		env, _ := json.Marshal(map[string]any{"status": "success", "data": map[string]any{"opaque": true}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(env)
	})
	mux.HandleFunc("/auth/recover/challenge/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(map[string]any{
			"status": "success",
			"data": map[string]any{
				"challenge":    "challenge-bytes",
				"nonce":        "nonce-bytes",
				"expires_at":   "2030-01-01T00:00:00Z",
				"user_id":      userID,
				"vault":        json.RawMessage(serveVault()),
				"vault_version": recVault.VaultVersion,
			},
		})
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
	mux.HandleFunc("/auth/recover/verify/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(map[string]any{
			"status": "success",
			"data": map[string]any{
				"user": map[string]any{"id": userID},
				"vault": json.RawMessage(serveVault()),
				"workspaces": []any{},
			},
		})
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
	mux.HandleFunc("/auth/recover/password/", func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Vault json.RawMessage `json:"vault"`
		}
		_ = json.NewDecoder(r.Body).Decode(&p)
		stored = p.Vault
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": nil})
	})
	mux.HandleFunc("/auth/vault/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			body, _ := json.Marshal(map[string]any{
				"status": "success",
				"data": map[string]any{
					"vault":         json.RawMessage(serveVault()),
					"vault_version": recVault.VaultVersion,
				},
			})
			w.Write(body)
			return
		}
		var p struct {
			Vault json.RawMessage `json:"vault"`
		}
		_ = json.NewDecoder(r.Body).Decode(&p)
		stored = p.Vault
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": nil})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := api.NewClient(func() string { return "" })
	client.BaseURL = server.URL
	svc := NewService(client)

	if _, err := svc.RecoverAccount(email, recoveryKey, newPassword); err != nil {
		t.Fatalf("RecoverAccount: %v", err)
	}
	if !config.GetOpaqueEnrolled() {
		t.Error("recovery did not re-enroll OPAQUE")
	}

	if stored == nil {
		t.Fatal("no vault stored after recovery")
	}
	var got vault.Vault
	if err := json.Unmarshal(stored, &got); err != nil {
		t.Fatalf("stored vault parse: %v", err)
	}
	if !got.IsSplit() {
		t.Fatalf("vault was downgraded from v2 (version=%d)", got.Version)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("post-recovery vault invalid: %v", err)
	}
	// The recovery key must still unlock the vault to the same private key.
	rvk, err := got.UnlockWithRecoveryKey(userID, recoveryKey)
	if err != nil {
		t.Fatalf("recovery key no longer unlocks: %v", err)
	}
	rpk, err := got.PrivateKey(userID, rvk)
	if err != nil || !bytes.Equal(rpk, privateKey) {
		t.Fatalf("post-recovery private key mismatch: %v", err)
	}
	// A v1-style unlock must be refused (v2 is never silently v1).
	if _, err := got.UnlockWithPassword(userID, newPassword); err == nil {
		t.Error("v2 vault unlocked via UnlockWithPassword (must fail closed)")
	}
}
