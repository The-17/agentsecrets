package sidecar

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bytemare/opaque"
)

// keyMaterial generates a freshly encoded deployment key set.
func keyMaterial(t *testing.T) string {
	t.Helper()
	conf := opaque.DefaultConfiguration()
	skm, err := GenerateKeyMaterial(conf)
	if err != nil {
		t.Fatalf("generate key material: %v", err)
	}
	encoded, err := FormatKeyMaterial(skm)
	if err != nil {
		t.Fatalf("format key material: %v", err)
	}
	if _, err := parseKeyMaterial(conf, encoded); err != nil {
		t.Fatalf("round trip of generated key material failed: %v", err)
	}
	return encoded
}

// newTestSidecar starts a sidecar backed by the given key material (hex).
// Tests pass the same value twice to model a restart.
func newTestSidecar(t *testing.T, material string) *httptest.Server {
	t.Helper()
	t.Setenv("OPAQUE_SIDECAR_TOKEN", "test-token")
	t.Setenv("OPAQUE_SERVER_KEY_MATERIAL", material)
	s, err := New(false)
	if err != nil {
		t.Fatal(err)
	}
	return newTestServer(t, s)
}

func newTestServer(t *testing.T, s *Sidecar) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/register/response":
			s.auth(s.handleRegisterResponse)(w, r)
		case "/v1/register/finish":
			s.auth(s.handleRegisterFinish)(w, r)
		case "/v1/login/start":
			s.auth(s.handleLoginStart)(w, r)
		case "/v1/login/finish":
			s.auth(s.handleLoginFinish)(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func post(t *testing.T, ts *httptest.Server, path string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil && resp.StatusCode == http.StatusOK {
		t.Fatalf("decode %s: %v", path, err)
	}
	return resp.StatusCode, out
}

func testB64(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

const (
	password = "sidecar-test-password"
	user     = "user@example.com"
)

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return raw
}

// register runs OPAQUE registration against the sidecar and returns the stored
// record blob Django would persist.
func register(t *testing.T, ts *httptest.Server, credID string) (string, error) {
	t.Helper()
	conf := opaque.DefaultConfiguration()
	dser, err := conf.Deserializer()
	if err != nil {
		t.Fatal(err)
	}
	client, err := conf.Client()
	if err != nil {
		t.Fatal(err)
	}
	regReq, err := client.RegistrationInit([]byte(password))
	if err != nil {
		t.Fatal(err)
	}
	code, resp := post(t, ts, "/v1/register/response", map[string]string{
		"reg_request":   testB64(regReq.Serialize()),
		"credential_id": credID,
	})
	if code != http.StatusOK {
		return "", fmt.Errorf("register/response: %d %v", code, resp)
	}
	regResp, err := dser.RegistrationResponse(decodeB64(t, resp["reg_response"].(string)))
	if err != nil {
		return "", fmt.Errorf("parse reg response: %w", err)
	}
	record, _, err := client.RegistrationFinalize(regResp, []byte(credID), nil)
	if err != nil {
		return "", fmt.Errorf("registration finalize: %w", err)
	}
	code, resp = post(t, ts, "/v1/register/finish", map[string]string{
		"reg_record":    testB64(record.Serialize()),
		"credential_id": credID,
	})
	if code != http.StatusOK {
		return "", fmt.Errorf("register/finish: %d %v", code, resp)
	}
	client.ClearState()
	return resp["record"].(string), nil
}

// login runs OPAQUE login against the sidecar with the stored record.
func login(t *testing.T, ts *httptest.Server, storedRecord, credID, loginPassword string) error {
	t.Helper()
	conf := opaque.DefaultConfiguration()
	dser, err := conf.Deserializer()
	if err != nil {
		t.Fatal(err)
	}
	client, err := conf.Client()
	if err != nil {
		t.Fatal(err)
	}
	ke1, err := client.GenerateKE1([]byte(loginPassword))
	if err != nil {
		t.Fatal(err)
	}
	code, resp := post(t, ts, "/v1/login/start", map[string]string{
		"ke1":           testB64(ke1.Serialize()),
		"record":        storedRecord,
		"credential_id": credID,
	})
	if code != http.StatusOK {
		return fmt.Errorf("login/start: %d %v", code, resp)
	}
	ke2, err := dser.KE2(decodeB64(t, resp["ke2"].(string)))
	if err != nil {
		return fmt.Errorf("parse ke2: %w", err)
	}
	ke3, sessionKey, _, err := client.GenerateKE3(ke2, []byte(credID), nil)
	if err != nil {
		return fmt.Errorf("client finish: %w", err)
	}
	code, resp = post(t, ts, "/v1/login/finish", map[string]string{
		"ke3":           testB64(ke3.Serialize()),
		"server_state":  resp["server_state"].(string),
		"credential_id": credID,
	})
	if code != http.StatusOK {
		return fmt.Errorf("login/finish: %d %v", code, resp)
	}
	if resp["session_key"].(string) != testB64(sessionKey) {
		return fmt.Errorf("session keys differ")
	}
	client.ClearState()
	return nil
}

func TestRegisterAndLogin(t *testing.T) {
	ts := newTestSidecar(t, keyMaterial(t))
	record, err := register(t, ts, user)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := login(t, ts, record, user, password); err != nil {
		t.Fatalf("login: %v", err)
	}
}

// TestLoginFinishStatusCodesSplitCredentialFromToken pins the status-code
// contract the server's OPAQUE client depends on: a rejected credential is 403
// (reject the user), a bad bearer token is 401 (fail closed and page someone).
// If these collapse into one code again, a typo is reported as an auth outage.
func TestLoginFinishStatusCodesSplitCredentialFromToken(t *testing.T) {
	ts := newTestSidecar(t, keyMaterial(t))
	record, err := register(t, ts, user)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	conf := opaque.DefaultConfiguration()
	dser, err := conf.Deserializer()
	if err != nil {
		t.Fatal(err)
	}
	client, err := conf.Client()
	if err != nil {
		t.Fatal(err)
	}
	ke1, err := client.GenerateKE1([]byte(password))
	if err != nil {
		t.Fatal(err)
	}
	code, start := post(t, ts, "/v1/login/start", map[string]string{
		"ke1":           testB64(ke1.Serialize()),
		"record":        record,
		"credential_id": user,
	})
	if code != http.StatusOK {
		t.Fatalf("login/start: %d %v", code, start)
	}
	ke2, err := dser.KE2(decodeB64(t, start["ke2"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	ke3, _, _, err := client.GenerateKE3(ke2, []byte(user), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the expected client MAC. The KE3 stays well formed and the
	// bearer token stays valid, which is exactly the wrong-password shape: the
	// server's credential check fails while everything around it is healthy.
	var state map[string]string
	if err := json.Unmarshal(decodeB64(t, start["server_state"].(string)), &state); err != nil {
		t.Fatal(err)
	}
	mac := state["client_mac"]
	// Flip the first byte, never the padding: the encoding must stay valid so
	// the server reaches the MAC comparison instead of rejecting the body.
	if mac[0] == 'A' {
		state["client_mac"] = "B" + mac[1:]
	} else {
		state["client_mac"] = "A" + mac[1:]
	}
	tamperedState, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}

	code, resp := post(t, ts, "/v1/login/finish", map[string]string{
		"ke3":           testB64(ke3.Serialize()),
		"server_state":  testB64(tamperedState),
		"credential_id": user,
	})
	if code != http.StatusForbidden {
		t.Fatalf("rejected credential: expected 403, got %d %v", code, resp)
	}

	// The same endpoint with no bearer token is a deployment problem, not a
	// user problem, and must stay 401.
	raw, _ := json.Marshal(map[string]string{"ke3": "AAAA", "server_state": "AAAA", "credential_id": user})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/login/finish", bytes.NewReader(raw))
	respUnauth, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer respUnauth.Body.Close()
	if respUnauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing bearer token: expected 401, got %d", respUnauth.StatusCode)
	}
}

func TestWrongPasswordRejected(t *testing.T) {
	ts := newTestSidecar(t, keyMaterial(t))
	record, err := register(t, ts, user)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	err = login(t, ts, record, user, "definitely-not-the-password")
	if err == nil {
		t.Fatal("login with the wrong password succeeded")
	}
	// A wrong password changes the OPRF output, so the masked response
	// unmasks to garbage and the client refuses before reaching
	// login/finish. Either the client-side rejection or a server-side 403
	// proves the login failed; both are acceptable. 403 rather than 401
	// because the bearer token is valid and the credential is not.
	if !strings.Contains(err.Error(), "client finish") && !strings.Contains(err.Error(), "login/finish: 403") {
		t.Fatalf("unexpected failure mode: %v", err)
	}
}

// TestKeyMaterialPersistsAcrossRestart is the regression test for the failure
// mode that would strand every enrolled user: a sidecar that invents new keys
// on start cannot authenticate records registered before the restart.
func TestKeyMaterialPersistsAcrossRestart(t *testing.T) {
	material := keyMaterial(t)
	first := newTestSidecar(t, material)
	record, err := register(t, first, user)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	first.Close()

	second := newTestSidecar(t, material)
	if err := login(t, second, record, user, password); err != nil {
		t.Fatalf("login after restart: %v", err)
	}
}

func TestMissingKeyMaterialRefusesToStart(t *testing.T) {
	t.Setenv("OPAQUE_SIDECAR_TOKEN", "test-token")
	t.Setenv("OPAQUE_SERVER_KEY_MATERIAL", "")
	if _, err := New(false); err == nil {
		t.Fatal("sidecar started without key material; enrolled records would be stranded")
	}
}

func TestMissingTokenRefusesToStart(t *testing.T) {
	t.Setenv("OPAQUE_SIDECAR_TOKEN", "")
	t.Setenv("OPAQUE_SERVER_KEY_MATERIAL", keyMaterial(t))
	if _, err := New(false); err == nil {
		t.Fatal("sidecar started without OPAQUE_SIDECAR_TOKEN")
	}
}

func TestAuthRequired(t *testing.T) {
	ts := newTestSidecar(t, keyMaterial(t))
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/login/start", strings.NewReader("{}"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request got %d", resp.StatusCode)
	}
}
