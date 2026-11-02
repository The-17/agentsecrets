package auth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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

	// sidecarURL, when set, makes the server advertise OPAQUE and proxy the
	// register endpoints to a real sidecar, so a test can prove recovery
	// re-enrolls the account. opaqueEnrolled flips when register/finish lands.
	sidecarURL     string
	opaqueEnrolled bool
}

// forwardOpaque proxies a CLI JSON body to the real sidecar, injecting the
// credential id the control plane owns, and wraps the answer in Django's
// CustomResponse.success envelope.
func (rs *recoveryServer) forwardOpaque(w http.ResponseWriter, r *http.Request, sidecarPath string) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	body["credential_id"] = "recovery@example.com"
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(r.Method, rs.sidecarURL+sidecarPath, bytes.NewReader(buf))
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
		rs.opaqueEnrolled = true
	}
	env, _ := json.Marshal(map[string]any{"status": "success", "data": json.RawMessage(out)})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(env)
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

	case "/auth/capabilities/":
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"data":   map[string]interface{}{"opaque": rs.sidecarURL != ""},
		})

	case "/auth/opaque/register/start/":
		rs.forwardOpaque(w, r, "/v1/register/response")

	case "/auth/opaque/register/finish/":
		rs.forwardOpaque(w, r, "/v1/register/finish")

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

// newRecoveryFixture builds a vault and a recovery server for a throwaway
// account, returning the pieces a recovery test needs.
func newRecoveryFixture(t *testing.T, userID, oldPassword string) (*recoveryServer, *vault.Vault, *vault.Material, []byte) {
	t.Helper()
	privateKey, _, err := crypto.GenerateKeypair()
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
	return rs, v, material, rawVault
}

// TestRecoverAccountClearsStaleOpaqueFlag locks the core bug: recovery clears
// the server's OPAQUE record and restores the password, so the local
// OpaqueEnrolled flag must be cleared or the login command would see "already
// enrolled" and never re-enroll, leaving the account password-only.
func TestRecoverAccountClearsStaleOpaqueFlag(t *testing.T) {
	setupAuthTest(t)
	const (
		userID      = "user-opaque-recovery"
		oldPassword = "forgotten-password"
		newPassword = "recovered-password"
	)
	rs, _, material, _ := newRecoveryFixture(t, userID, oldPassword)
	server := httptest.NewServer(http.HandlerFunc(rs.handler))
	defer server.Close()

	// The account had enrolled OPAQUE before recovering.
	if err := config.SetOpaqueEnrolled(true); err != nil {
		t.Fatal(err)
	}

	client := api.NewClient(func() string { return config.GetAccessToken() })
	client.BaseURL = server.URL
	svc := NewService(client)

	result, err := svc.RecoverAccount("test@example.com", vault.EncodeRecoveryKey(material.RecoveryKey), newPassword)
	if err != nil {
		t.Fatalf("RecoverAccount: %v", err)
	}
	if config.GetOpaqueEnrolled() {
		t.Error("OpaqueEnrolled still true after recovery; login would never re-enroll")
	}
	if !result.RecoveryConfirmed {
		t.Error("result.RecoveryConfirmed = false, want true (using the recovery key proves possession)")
	}
}

// TestRecoverAccountReenrollsOpaque proves recovery leaves the account able to
// re-enroll: with a live sidecar and capabilities reporting OPAQUE, RecoverAccount
// must drive register/start + register/finish and record the enrollment.
func TestRecoverAccountReenrollsOpaque(t *testing.T) {
	setupAuthTest(t)
	sidecar := startSidecar(t)
	const (
		userID      = "user-reenroll"
		oldPassword = "forgotten-password"
		newPassword = "recovered-password"
	)
	rs, _, material, _ := newRecoveryFixture(t, userID, oldPassword)
	rs.sidecarURL = sidecar
	server := httptest.NewServer(http.HandlerFunc(rs.handler))
	defer server.Close()

	if err := config.SetOpaqueEnrolled(false); err != nil {
		t.Fatal(err)
	}

	client := api.NewClient(func() string { return config.GetAccessToken() })
	client.BaseURL = server.URL
	svc := NewService(client)

	result, err := svc.RecoverAccount("test@example.com", vault.EncodeRecoveryKey(material.RecoveryKey), newPassword)
	if err != nil {
		t.Fatalf("RecoverAccount: %v", err)
	}
	if !result.RecoveryConfirmed {
		t.Fatal("recovery not confirmed; re-enrollment should be gated on it")
	}
	if !rs.opaqueEnrolled {
		t.Fatal("register/finish was not called; the recovered account was not re-enrolled")
	}
	if !config.GetOpaqueEnrolled() {
		t.Error("OpaqueEnrolled not set after successful re-enrollment")
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
