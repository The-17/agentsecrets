package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/vault"
)

// recoveryServer simulates the three recovery endpoints and records the vault
// the client writes back, so the test can prove the new password really
// unwraps it.
type recoveryServer struct {
	userID          string
	challenge       string
	nonce           string
	vault           *vault.Vault
	rawVault        []byte
	rawRecoveryView []byte
	newVault        *vault.Vault
	expectedVer     int
	passwordCall    bool
}

func (rs *recoveryServer) handler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/auth/recover/challenge/":
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"challenge":     rs.challenge,
				"nonce":         rs.nonce,
				"expires_at":    time.Now().Add(5 * time.Minute).Format(time.RFC3339),
				"user_id":       rs.userID,
				"vault":         json.RawMessage(rs.rawRecoveryView),
				"vault_version": rs.vault.VaultVersion,
			},
		})

	case "/auth/recover/verify/":
		var body struct {
			Email     string `json:"email"`
			Nonce     string `json:"nonce"`
			Signature string `json:"signature"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sig, err := base64.StdEncoding.DecodeString(body.Signature)
		if err != nil || body.Nonce != rs.nonce {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		pub, err := base64.StdEncoding.DecodeString(rs.vault.VaultPubKey)
		if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, []byte(rs.challenge), sig) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"access":        "recovery-access",
				"refresh":       "recovery-refresh",
				"expires_at":    "2030-01-01T00:00:00Z",
				"vault":         json.RawMessage(rs.rawVault),
				"vault_version": rs.vault.VaultVersion,
				"user": map[string]interface{}{
					"id":         rs.userID,
					"public_key": "",
				},
				"workspaces": []interface{}{},
			},
		})

	case "/auth/recover/password/":
		var body struct {
			NewPassword         string          `json:"new_password"`
			KeySalt             string          `json:"key_salt"`
			EncryptedPrivateKey string          `json:"encrypted_private_key"`
			Vault               json.RawMessage `json:"vault"`
			ExpectedVersion     int             `json:"expected_version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var next vault.Vault
		if err := json.Unmarshal(body.Vault, &next); err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		if err := next.Verify(rs.userID); err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		rs.expectedVer = body.ExpectedVersion
		rs.newVault = &next
		rs.passwordCall = true
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "ok"})

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestRecoverAccountUnlocksAndSetsNewPassword(t *testing.T) {
	setupAuthTest(t)
	const (
		userID      = "user-123"
		oldPassword = "forgotten-password"
		newPassword = "recovered-password"
	)
	privateKey, publicKey, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	v, material, err := vault.Create(userID, oldPassword, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	rawVault, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	rs := &recoveryServer{
		userID:          userID,
		nonce:           "fixed-nonce",
		vault:           v,
		rawVault:        rawVault,
		rawRecoveryView: recoveryViewJSON(t, v),
		challenge:       fmt.Sprintf("as-vault-recover-v1\nuser:%s\nnonce:fixed-nonce\nexpires:%d\n", userID, time.Now().Add(5*time.Minute).Unix()),
	}

	server := httptest.NewServer(http.HandlerFunc(rs.handler))
	defer server.Close()

	client := api.NewClient(func() string { return config.GetAccessToken() })
	client.BaseURL = server.URL
	svc := NewService(client)

	result, err := svc.RecoverAccount("test@example.com", vault.EncodeRecoveryKey(material.RecoveryKey), newPassword)
	if err != nil {
		t.Fatalf("RecoverAccount: %v", err)
	}
	if !rs.passwordCall {
		t.Fatal("password reset endpoint was not called")
	}
	if rs.expectedVer != 1 {
		t.Fatalf("expected_version %d, want 1", rs.expectedVer)
	}
	if result.VaultVersion != 2 {
		t.Fatalf("result version %d, want 2", result.VaultVersion)
	}
	if config.GetAccessToken() != "recovery-access" {
		t.Fatal("recovery session was not stored")
	}
	if config.GetUserID() != userID {
		t.Fatalf("user id %q, want %q", config.GetUserID(), userID)
	}

	// The vault the server received must open with the new password and not
	// the old one. This is the end-to-end proof that rewrap worked.
	vk, err := rs.newVault.UnlockWithPassword(userID, newPassword)
	if err != nil {
		t.Fatalf("new password does not unlock the stored vault: %v", err)
	}
	recovered, err := rs.newVault.PrivateKey(userID, vk)
	if err != nil {
		t.Fatal(err)
	}
	if string(recovered) != string(privateKey) {
		t.Fatal("recovered private key does not match the original")
	}
	if _, err := rs.newVault.UnlockWithPassword(userID, oldPassword); err == nil {
		t.Fatal("old password still unlocks the vault")
	}

	// Public key is derivable without the legacy blob.
	derived, err := crypto.PublicFromPrivate(recovered)
	if err != nil || string(derived) != string(publicKey) {
		t.Fatalf("derived public key mismatch: %v", err)
	}
}

func TestRecoverAccountRejectsWrongRecoveryKey(t *testing.T) {
	setupAuthTest(t)
	const userID = "user-123"
	privateKey, _, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	v, _, err := vault.Create(userID, "password123", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, _, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, otherMaterial, err := vault.Create("other-user", "password123", otherKey)
	if err != nil {
		t.Fatal(err)
	}
	rawVault, _ := json.Marshal(v)

	rs := &recoveryServer{
		userID:          userID,
		nonce:           "fixed-nonce",
		vault:           v,
		rawVault:        rawVault,
		rawRecoveryView: recoveryViewJSON(t, v),
		challenge:       fmt.Sprintf("as-vault-recover-v1\nuser:%s\nnonce:fixed-nonce\nexpires:%d\n", userID, time.Now().Add(5*time.Minute).Unix()),
	}
	server := httptest.NewServer(http.HandlerFunc(rs.handler))
	defer server.Close()

	client := api.NewClient(func() string { return "" })
	client.BaseURL = server.URL
	svc := NewService(client)

	if _, err := svc.RecoverAccount("test@example.com", vault.EncodeRecoveryKey(otherMaterial.RecoveryKey), "new-password"); err == nil {
		t.Fatal("a recovery key from another account unlocked this vault")
	}
	if rs.passwordCall {
		t.Fatal("password reset ran without a valid unlock")
	}
}

// recoveryViewJSON strips the challenge response down to what the server
// actually exposes before authentication: recovery envelopes only, no proof,
// no bridge, no password envelope.
func recoveryViewJSON(t *testing.T, v *vault.Vault) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var view map[string]interface{}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	delete(view, "proof")
	delete(view, "bridge")
	envelopes, _ := view["envelopes"].([]interface{})
	recovery := make([]interface{}, 0, len(envelopes))
	for _, envelope := range envelopes {
		item, ok := envelope.(map[string]interface{})
		if ok && item["type"] == "recovery" {
			recovery = append(recovery, item)
		}
	}
	view["envelopes"] = recovery
	out, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
