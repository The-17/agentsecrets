// Command opaque-sidecar runs the OPAQUE (RFC 9807) server side for the
// AgentSecrets control plane.
//
// Django owns accounts and persistence; this process owns the OPAQUE server
// key material and the protocol math. It is stateless across requests: every
// call carries the client record or the server state blob from the previous
// call, so the sidecar can restart freely and scale horizontally.
//
// The sidecar binds to 127.0.0.1 (or the unix socket) inside the server's
// container. Django reaches it over localhost with a static bearer token set
// at startup. It is never exposed publicly.
//
// Endpoints (all JSON, base64 for binary fields):
//
//	POST /v1/register/response {reg_request, credential_id} -> {reg_response}
//	POST /v1/register/finish   {reg_record, credential_id}  -> {record}  (canonical, with masking nonce)
//	POST /v1/login/start       {ke1, credential_id, record} -> {ke2, server_state}
//	POST /v1/login/finish      {ke3, server_state}          -> {ok, session_key}
//	GET  /healthz                                           -> 200
//
// On /v1/register/finish the sidecar stores the client's record bytes verbatim
// and wraps them with the credential id; Django only ever handles opaque blobs.
// The masking nonce lives inside the record, keeping login stateless.
//
// Long-term key material comes from OPAQUE_SERVER_KEY_MATERIAL (hex). It must
// be identical across restarts and replicas: a record registered under one key
// set cannot authenticate under another. The token comes from
// OPAQUE_SIDECAR_TOKEN. Both are required, and the process exits without them
// rather than silently generating keys that would strand enrolled accounts.
package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bytemare/opaque"
)

const bearerPrefix = "Bearer "

type sidecar struct {
	conf  *opaque.Configuration
	skm   *opaque.ServerKeyMaterial
	token string
}

type request struct {
	RegRequest   string `json:"reg_request,omitempty"`
	RegRecord    string `json:"reg_record,omitempty"`
	KE1          string `json:"ke1,omitempty"`
	KE3          string `json:"ke3,omitempty"`
	Record       string `json:"record,omitempty"`
	ServerState  string `json:"server_state,omitempty"`
	CredentialID string `json:"credential_id"`
}

type response struct {
	RegResponse string `json:"reg_response,omitempty"`
	Record      string `json:"record,omitempty"`
	KE2         string `json:"ke2,omitempty"`
	ServerState string `json:"server_state,omitempty"`
	OK          bool   `json:"ok,omitempty"`
	SessionKey  string `json:"session_key,omitempty"`
}

// newSidecar loads the server's long-term OPAQUE key material from the
// environment. It is deliberately NOT generated here: records registered
// against one key set cannot be authenticated against another, so a restart
// with fresh keys would lock every enrolled account out. The key material is
// a deployment secret, generated once (see -dev-generate-keys) and reused.
func newSidecar(devGenerateKeys bool) (*sidecar, error) {
	conf := opaque.DefaultConfiguration()
	token := os.Getenv("OPAQUE_SIDECAR_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("OPAQUE_SIDECAR_TOKEN is required")
	}

	encoded := os.Getenv("OPAQUE_SERVER_KEY_MATERIAL")
	if encoded == "" {
		if !devGenerateKeys {
			return nil, fmt.Errorf("OPAQUE_SERVER_KEY_MATERIAL is required: " +
				"set it to the sk:pk:oprf value printed by -dev-generate-keys, or pass -dev-generate-keys for local development")
		}
		generated, err := generateKeyMaterial(conf)
		if err != nil {
			return nil, err
		}
		printable, err := formatKeyMaterial(generated)
		if err != nil {
			return nil, err
		}
		log.Printf("WARNING: generated ephemeral OPAQUE key material; "+
			"records do not survive a restart. OPAQUE_SERVER_KEY_MATERIAL=%s", printable)
		return &sidecar{conf: conf, skm: generated, token: token}, nil
	}

	skm, err := parseKeyMaterial(conf, encoded)
	if err != nil {
		return nil, fmt.Errorf("OPAQUE_SERVER_KEY_MATERIAL: %w", err)
	}
	return &sidecar{conf: conf, skm: skm, token: token}, nil
}

func (s *sidecar) server() (*opaque.Server, error) {
	server, err := s.conf.Server()
	if err != nil {
		return nil, err
	}
	if err := server.SetKeyMaterial(s.skm); err != nil {
		return nil, err
	}
	return server, nil
}

func (s *sidecar) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, bearerPrefix) ||
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, bearerPrefix)), []byte(s.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func decodeRequest(r *http.Request) (*request, error) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, fmt.Errorf("parse body: %w", err)
	}
	if req.CredentialID == "" {
		return nil, fmt.Errorf("credential_id is required")
	}
	return &req, nil
}

func writeJSON(w http.ResponseWriter, resp response) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func b64(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

func unb64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func (s *sidecar) handleRegisterResponse(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	raw, err := unb64(req.RegRequest)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("reg_request: %w", err))
		return
	}
	server, err := s.server()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	dser, err := s.conf.Deserializer()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	regReq, err := dser.RegistrationRequest(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("reg_request: %w", err))
		return
	}
	regResp, err := server.RegistrationResponse(regReq, []byte(req.CredentialID), nil)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, response{RegResponse: b64(regResp.Serialize())})
}

func (s *sidecar) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	raw, err := unb64(req.RegRecord)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("reg_record: %w", err))
		return
	}
	// Store the record bytes exactly as the client sent them. Re-serializing
	// through the deserializer risks losing envelope layout details; the
	// client's bytes are the canonical form.
	stored, err := json.Marshal(map[string]string{
		"credential_id": req.CredentialID,
		"record":        b64(raw),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, response{Record: b64(stored)})
}

func (s *sidecar) handleLoginStart(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	ke1Raw, err := unb64(req.KE1)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("ke1: %w", err))
		return
	}
	recordRaw, err := unb64(req.Record)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("record: %w", err))
		return
	}
	var stored struct {
		CredentialID string `json:"credential_id"`
		Record       string `json:"record"`
	}
	if err := json.Unmarshal(recordRaw, &stored); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("record: %w", err))
		return
	}
	recordBytes, err := unb64(stored.Record)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("record: %w", err))
		return
	}
	dser, err := s.conf.Deserializer()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	ke1, err := dser.KE1(ke1Raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("ke1: %w", err))
		return
	}
	regRecord, err := dser.RegistrationRecord(recordBytes)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("record: %w", err))
		return
	}
	server, err := s.server()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	clientRecord := &opaque.ClientRecord{
		RegistrationRecord:   regRecord,
		CredentialIdentifier: []byte(stored.CredentialID),
		ClientIdentity:       []byte(req.CredentialID),
	}
	ke2, output, err := server.GenerateKE2(ke1, clientRecord)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	// server_state carries what login/finish needs: the client MAC. It is a
	// short-lived secret handed to Django for the duration of one login
	// attempt and never persisted.
	state, err := json.Marshal(map[string]string{"client_mac": b64(output.ClientMAC), "session_key": b64(output.SessionSecret)})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, response{KE2: b64(ke2.Serialize()), ServerState: b64(state)})
}

func (s *sidecar) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	stateRaw, err := unb64(req.ServerState)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("server_state: %w", err))
		return
	}
	var state struct {
		ClientMAC  string `json:"client_mac"`
		SessionKey string `json:"session_key"`
	}
	if err := json.Unmarshal(stateRaw, &state); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("server_state: %w", err))
		return
	}
	ke3Raw, err := unb64(req.KE3)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("ke3: %w", err))
		return
	}
	if len(ke3Raw) != 64 {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("ke3: wrong length %d", len(ke3Raw)))
		return
	}
	expected, err := unb64(state.ClientMAC)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("server_state: %w", err))
		return
	}
	if subtle.ConstantTimeCompare(ke3Raw, expected) != 1 {
		writeErr(w, http.StatusUnauthorized, fmt.Errorf("authentication failed"))
		return
	}
	writeJSON(w, response{OK: true, SessionKey: state.SessionKey})
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8790", "listen address (loopback only)")
	devGenerateKeys := flag.Bool("dev-generate-keys", false,
		"generate throwaway key material when OPAQUE_SERVER_KEY_MATERIAL is unset (local development only)")
	printKeys := flag.Bool("print-keys", false,
		"print a fresh key material value for OPAQUE_SERVER_KEY_MATERIAL and exit")
	flag.Parse()

	if *printKeys {
		conf := opaque.DefaultConfiguration()
		skm, err := generateKeyMaterial(conf)
		if err != nil {
			log.Fatal(err)
		}
		printable, err := formatKeyMaterial(skm)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(printable)
		return
	}

	s, err := newSidecar(*devGenerateKeys)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/v1/register/response", s.auth(s.handleRegisterResponse))
	mux.Handle("/v1/register/finish", s.auth(s.handleRegisterFinish))
	mux.Handle("/v1/login/start", s.auth(s.handleLoginStart))
	mux.Handle("/v1/login/finish", s.auth(s.handleLoginFinish))

	server := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	host, port, _ := net.SplitHostPort(*addr)
	if host != "127.0.0.1" && host != "localhost" && host != "" {
		log.Fatalf("refusing to bind non-loopback address %q: the sidecar is internal only", host)
	}
	log.Printf("opaque sidecar listening on %s", net.JoinHostPort(host, port))
	log.Fatal(server.ListenAndServe())
}
