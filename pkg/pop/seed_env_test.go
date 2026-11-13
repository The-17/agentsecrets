package pop

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSeedEnvReproducesProofKey proves the option-A contract at the CLI side:
// agent create prints the seed, and a workload that copies it into
// AGENTSECRETS_POP_SEED (with no OS keychain) regenerates the exact proof key
// bound to its token. Without this, a deployment host with only the token +
// seed could not satisfy the resolver, and cloud mode would break for every
// new agent once --no-pop is gone.
func TestSeedEnvReproducesProofKey(t *testing.T) {
	signer, err := NewProofSigner()
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()

	// Simulate the value agent create prints next to the token.
	seedB64 := base64.StdEncoding.EncodeToString(signer.Seed())
	t.Setenv(SeedEnv, seedB64)

	// A fresh process would call this at startup; it must pick up the env seed.
	if err := LoadSignerFromEnvironment(); err != nil {
		t.Fatalf("LoadSignerFromEnvironment: %v", err)
	}
	defer SetProofSigner(nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/workloads/env", nil)
	req.Header.Set("Authorization", "Bearer agt_whatever")
	AttachProof(req, "agt_whatever")

	sigB64 := req.Header.Get(ProofHeader)
	ts := req.Header.Get(TimestampHeader)
	if sigB64 == "" || ts == "" {
		t.Fatal("AttachProof produced no proof headers from SeedEnv")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(http.MethodPost + "\n" + "/v1/workloads/env" + "\n" + ts)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("proof from SeedEnv does not verify against the token's bound public key")
	}
}
