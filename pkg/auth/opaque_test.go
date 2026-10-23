package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/bytemare/opaque"

	"github.com/The-17/agentsecrets/pkg/api"
)

// fakeOpaqueServer models the Django + sidecar contract for the four OPAQUE
// endpoints, using the real bytemare server so the client is exercised against
// real cryptography rather than a scripted reply.
type fakeOpaqueServer struct {
	t      *testing.T
	server *opaque.Server

	mu       sync.Mutex
	record   []byte // stored registration record, as the sidecar would hold it
	credID   string
	enrolled bool

	// failLoginStart makes login/start return the given status, for testing
	// the client's handling of a refused exchange.
	failLoginStart int
}

func newFakeOpaqueServer(t *testing.T) *fakeOpaqueServer {
	t.Helper()
	conf := opaque.DefaultConfiguration()
	secret, public := conf.KeyGen()
	if secret == nil || public == nil {
		t.Fatal("key generation failed")
	}
	skm := &opaque.ServerKeyMaterial{
		PrivateKey:     secret,
		PublicKeyBytes: public.Encode(),
		OPRFGlobalSeed: conf.GenerateOPRFSeed(),
	}
	srv, err := conf.Server()
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	if err := srv.SetKeyMaterial(skm); err != nil {
		t.Fatalf("set key material: %v", err)
	}
	return &fakeOpaqueServer{t: t, server: srv}
}

func (f *fakeOpaqueServer) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/auth/capabilities/", func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, http.StatusOK, map[string]any{
			"password": true, "opaque": true,
		})
	})

	mux.HandleFunc("/auth/opaque/register/start/", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)

		raw, err := base64.StdEncoding.DecodeString(body["reg_request"])
		if err != nil {
			http.Error(w, "bad reg_request", http.StatusBadRequest)
			return
		}
		dser, _ := opaque.DefaultConfiguration().Deserializer()
		regReq, err := dser.RegistrationRequest(raw)
		if err != nil {
			http.Error(w, "bad reg_request", http.StatusBadRequest)
			return
		}
		regResp, err := f.server.RegistrationResponse(regReq, []byte(body["credential_id"]), nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeEnvelope(w, http.StatusOK, map[string]any{
			"reg_response":  base64.StdEncoding.EncodeToString(regResp.Serialize()),
			"credential_id": body["credential_id"],
		})
	})

	mux.HandleFunc("/auth/opaque/register/finish/", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		raw, err := base64.StdEncoding.DecodeString(body["reg_record"])
		if err != nil {
			http.Error(w, "bad reg_record", http.StatusBadRequest)
			return
		}
		// Mirror the sidecar: store the client's bytes verbatim, wrapped with
		// the credential id.
		stored, _ := json.Marshal(map[string]string{
			"credential_id": body["credential_id"],
			"record":        base64.StdEncoding.EncodeToString(raw),
		})
		f.mu.Lock()
		f.record = stored
		f.credID = body["credential_id"]
		f.enrolled = true
		f.mu.Unlock()

		writeEnvelope(w, http.StatusOK, map[string]any{
			"record": base64.StdEncoding.EncodeToString(stored),
		})
	})

	mux.HandleFunc("/auth/opaque/login/start/", func(w http.ResponseWriter, r *http.Request) {
		if f.failLoginStart != 0 {
			w.WriteHeader(f.failLoginStart)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "invalid_credentials"})
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)

		// The record must come from the server's own state. The client is not
		// allowed to supply it, which is what makes a second device work.
		if _, supplied := body["record"]; supplied {
			http.Error(w, "client must not send the record", http.StatusBadRequest)
			return
		}

		f.mu.Lock()
		record, credID := f.record, f.credID
		f.mu.Unlock()
		if record == nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "invalid_credentials"})
			return
		}

		var stored struct {
			CredentialID string `json:"credential_id"`
			Record       string `json:"record"`
		}
		if err := json.Unmarshal(record, &stored); err != nil {
			http.Error(w, "bad stored record", http.StatusInternalServerError)
			return
		}
		recordBytes, err := base64.StdEncoding.DecodeString(stored.Record)
		if err != nil {
			http.Error(w, "bad stored record", http.StatusInternalServerError)
			return
		}

		dser, _ := opaque.DefaultConfiguration().Deserializer()
		ke1Raw, err := base64.StdEncoding.DecodeString(body["ke1"])
		if err != nil {
			http.Error(w, "bad ke1", http.StatusBadRequest)
			return
		}
		ke1, err := dser.KE1(ke1Raw)
		if err != nil {
			http.Error(w, "bad ke1", http.StatusBadRequest)
			return
		}
		regRecord, err := dser.RegistrationRecord(recordBytes)
		if err != nil {
			http.Error(w, "bad record", http.StatusInternalServerError)
			return
		}

		clientRecord := &opaque.ClientRecord{
			RegistrationRecord:   regRecord,
			CredentialIdentifier: []byte(stored.CredentialID),
			ClientIdentity:       []byte(credID),
		}
		ke2, output, err := f.server.GenerateKE2(ke1, clientRecord)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		state, _ := json.Marshal(map[string]string{
			"client_mac":  base64.StdEncoding.EncodeToString(output.ClientMAC),
			"session_key": base64.StdEncoding.EncodeToString(output.SessionSecret),
		})
		writeEnvelope(w, http.StatusOK, map[string]any{
			"ke2":          base64.StdEncoding.EncodeToString(ke2.Serialize()),
			"server_state": base64.StdEncoding.EncodeToString(state),
		})
	})

	mux.HandleFunc("/auth/opaque/login/finish/", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)

		stateRaw, err := base64.StdEncoding.DecodeString(body["server_state"])
		if err != nil {
			http.Error(w, "bad server_state", http.StatusBadRequest)
			return
		}
		var state struct {
			ClientMAC  string `json:"client_mac"`
			SessionKey string `json:"session_key"`
		}
		if err := json.Unmarshal(stateRaw, &state); err != nil {
			http.Error(w, "bad server_state", http.StatusBadRequest)
			return
		}
		ke3Raw, err := base64.StdEncoding.DecodeString(body["ke3"])
		if err != nil || len(ke3Raw) == 0 {
			http.Error(w, "bad ke3", http.StatusBadRequest)
			return
		}
		dser, _ := opaque.DefaultConfiguration().Deserializer()
		ke3, err := dser.KE3(ke3Raw)
		if err != nil {
			http.Error(w, "bad ke3", http.StatusBadRequest)
			return
		}
		wantMAC, err := base64.StdEncoding.DecodeString(state.ClientMAC)
		if err != nil {
			http.Error(w, "bad client_mac", http.StatusInternalServerError)
			return
		}
		// The library verifies the client MAC over the KE3 transcript, which is
		// what a wrong password fails.
		if err := f.server.LoginFinish(ke3, wantMAC); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "invalid_credentials"})
			return
		}

		writeEnvelope(w, http.StatusOK, map[string]any{
			"access":        "access-token",
			"refresh":       "refresh-token",
			"expires_at":    "2030-01-01T00:00:00Z",
			"session_key":   state.SessionKey,
			"vault_version": 3,
			"vault":         map[string]any{"version": 1},
			"user":          map[string]any{"id": "user-1", "email": "e2e@example.com", "public_key": ""},
			"workspaces":    []any{},
		})
	})

	return mux
}

func writeEnvelope(w http.ResponseWriter, status int, data map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "success", "data": data,
	})
}

func newOpaqueTestService(t *testing.T, h http.Handler) *Service {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	client := api.NewClientWithURL(ts.URL, func() string { return "test-token" })
	return NewService(client)
}

// TestOpaqueEnrollThenLoginRoundTrips is the core contract: a password enrolled
// through OPAQUE can be used to log in, and the server's stored record is the
// only state involved.
func TestOpaqueEnrollThenLoginRoundTrips(t *testing.T) {
	fake := newFakeOpaqueServer(t)
	svc := newOpaqueTestService(t, fake.handler())

	const email = "e2e@example.com"
	const password = "correct-horse-battery-staple"

	if err := svc.EnrollOpaque(email, password); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	resp, err := svc.opaqueLogin(email, password)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if resp.Data.SessionKey == "" {
		t.Fatal("login succeeded but returned no session key")
	}
	if resp.Data.User.ID != "user-1" {
		t.Fatalf("unexpected user: %q", resp.Data.User.ID)
	}
}

// TestOpaqueLoginWrongPasswordFails proves a wrong password cannot complete the
// exchange. The client must fail before or at login/finish, never succeed.
func TestOpaqueLoginWrongPasswordFails(t *testing.T) {
	fake := newFakeOpaqueServer(t)
	svc := newOpaqueTestService(t, fake.handler())

	const email = "e2e@example.com"
	if err := svc.EnrollOpaque(email, "the-real-password"); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	if _, err := svc.opaqueLogin(email, "definitely-not-the-password"); err == nil {
		t.Fatal("login with the wrong password succeeded")
	}
}

// TestOpaqueLoginBeforeEnrollmentFails proves an unenrolled account cannot
// complete an OPAQUE login, and the error is reported rather than swallowed.
func TestOpaqueLoginBeforeEnrollmentFails(t *testing.T) {
	fake := newFakeOpaqueServer(t)
	svc := newOpaqueTestService(t, fake.handler())

	if _, err := svc.opaqueLogin("nobody@example.com", "any-password"); err == nil {
		t.Fatal("login before enrollment succeeded")
	}
}

// TestOpaqueLoginDoesNotSendRecord is the regression test for the bug that
// limited login to the enrolling device: the client must never send the
// registration record, because the server owns it.
func TestOpaqueLoginDoesNotSendRecord(t *testing.T) {
	fake := newFakeOpaqueServer(t)
	var seen []byte
	var mu sync.Mutex

	mux := fake.handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/opaque/login/start/" {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			seen = body
			mu.Unlock()
			// Restore the body so the inner handler still sees the request.
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)

	client := api.NewClientWithURL(ts.URL, func() string { return "test-token" })
	svc := NewService(client)

	const email = "e2e@example.com"
	const password = "correct-horse-battery-staple"
	if err := svc.EnrollOpaque(email, password); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := svc.opaqueLogin(email, password); err != nil {
		t.Fatalf("login: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	var payload map[string]string
	if err := json.Unmarshal(seen, &payload); err != nil {
		t.Fatalf("login/start body was not JSON: %v", err)
	}
	if _, present := payload["record"]; present {
		t.Fatal("login/start sent a registration record; the server owns it")
	}
	for _, want := range []string{"email", "ke1", "credential_id"} {
		if payload[want] == "" {
			t.Fatalf("login/start omitted %q", want)
		}
	}
}

// TestOpaqueCredentialIDIsStableAndOpaque pins the two properties the server
// depends on: the id never changes for an account, and it is not the raw email.
func TestOpaqueCredentialIDIsStableAndOpaque(t *testing.T) {
	a := opaqueCredentialID("User@Example.com")
	b := opaqueCredentialID("user@example.com")
	if a != b {
		t.Fatalf("credential id is case sensitive: %q vs %q", a, b)
	}
	if a == "" || strings.Contains(a, "@") {
		t.Fatalf("credential id leaks or is empty: %q", a)
	}
	if opaqueCredentialID("other@example.com") == a {
		t.Fatal("different accounts share a credential id")
	}
	if len(a) != 36 {
		t.Fatalf("credential id is not a UUID: %q", a)
	}
}

// TestFetchCapabilitiesReportsOpaque proves the client reads the server's
// advertisement, which gates enrollment.
func TestFetchCapabilitiesReportsOpaque(t *testing.T) {
	fake := newFakeOpaqueServer(t)
	svc := newOpaqueTestService(t, fake.handler())

	caps, err := svc.FetchCapabilities()
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	if !caps.Opaque {
		t.Fatal("capabilities did not report opaque support")
	}
}

// TestFetchCapabilitiesToleratesOldServer proves a server without the endpoint
// yields empty capabilities rather than an error, so an old deployment does not
// break the CLI.
func TestFetchCapabilitiesToleratesOldServer(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(ts.Close)
	client := api.NewClientWithURL(ts.URL, func() string { return "" })
	svc := NewService(client)

	caps, err := svc.FetchCapabilities()
	if err != nil {
		t.Fatalf("capabilities on an old server returned an error: %v", err)
	}
	if caps.Opaque {
		t.Fatal("an old server reported opaque support")
	}
}
