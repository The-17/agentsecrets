package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"crypto/rand"

	"golang.org/x/crypto/nacl/box"
)

// TestFetchWorkloadEnvSealed_RoundTrip proves the CLI can request a sealed
// environment from the resolver and recover the exact secret map, and that the
// response body on the wire contains NO plaintext secret values.
func TestFetchWorkloadEnvSealed_RoundTrip(t *testing.T) {
	want := map[string]string{
		"STRIPE_KEY": "sk_live_secret_value_ONE",
		"AWS_KEY":    "akia_example_value_TWO",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req struct {
			ClientPublicKey string `json:"client_public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var clientPub [32]byte
		b, err := hex.DecodeString(req.ClientPublicKey)
		if err != nil || len(b) != 32 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		copy(clientPub[:], b)

		payload, _ := json.Marshal(want)
		sealed, err := box.SealAnonymous(nil, payload, &clientPub, rand.Reader)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body := WorkloadEnvSealedResponse{
			Sealed: base64.StdEncoding.EncodeToString(sealed),
			Nonce:  "deadbeefdeadbeef",
		}
		buf, _ := json.Marshal(body)
		// HARD requirement: plaintext secret values must never appear on the wire.
		if strings.Contains(string(buf), want["STRIPE_KEY"]) || strings.Contains(string(buf), want["AWS_KEY"]) {
			t.Errorf("HARD FAIL: plaintext secret value leaked into resolver response body: %s", string(buf))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf)
	}))
	defer srv.Close()

	got, err := FetchWorkloadEnvSealed(context.Background(), srv.URL, "tok", "production", "")
	if err != nil {
		t.Fatalf("FetchWorkloadEnvSealed: %v", err)
	}
	if got["STRIPE_KEY"] != want["STRIPE_KEY"] || got["AWS_KEY"] != want["AWS_KEY"] {
		t.Fatalf("recovered environment mismatch: %+v", got)
	}
}

// A response sealed to a different key must fail to open: the client must not
// silently accept a box it cannot decrypt.
func TestFetchWorkloadEnvSealed_WrongKeyFails(t *testing.T) {
	// Attacker key (seals to its own pubkey, not the client's).
	attackerPub, _, _ := box.GenerateKey(rand.Reader)
	sealed, _ := box.SealAnonymous(nil, []byte(`{"STRIPE_KEY":"x"}`), attackerPub, rand.Reader)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(WorkloadEnvSealedResponse{
			Sealed: base64.StdEncoding.EncodeToString(sealed),
		})
	}))
	defer srv.Close()

	if _, err := FetchWorkloadEnvSealed(context.Background(), srv.URL, "tok", "", ""); err == nil {
		t.Fatal("expected an error when the response is not sealed to the client's key")
	}
}
