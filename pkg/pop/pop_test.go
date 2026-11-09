package pop

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// popMessage mirrors server.popMessage in the cloud resolver. If the two drift,
// proof-of-possession silently breaks, so the test pins the exact construction.
func popMessage(method, path, ts string) []byte {
	return []byte(method + "\n" + path + "\n" + ts)
}

func verifyAttach(t *testing.T, req *http.Request, pub ed25519.PublicKey) {
	t.Helper()
	sigB64 := req.Header.Get(ProofHeader)
	ts := req.Header.Get(TimestampHeader)
	if sigB64 == "" || ts == "" {
		t.Fatal("Attach must set both proof and timestamp headers")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatalf("decoded signature wrong size: %v", err)
	}
	tsNum, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if age := time.Now().Unix() - tsNum; age < -5 || age > 5 {
		t.Fatalf("timestamp not current: age=%d", age)
	}
	if !ed25519.Verify(pub, popMessage(req.Method, req.URL.Path, ts), sig) {
		t.Fatal("resolver-style verification must accept the signed proof")
	}
}

func TestProofSigner_AttachProducesVerifiableProof(t *testing.T) {
	signer, err := NewProofSigner()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads/env", nil)
	signer.Attach(req)
	verifyAttach(t, req, signer.PublicKey())
}

func TestProofSigner_TamperedPathFails(t *testing.T) {
	signer, _ := NewProofSigner()
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads/env", nil)
	signer.Attach(req)
	sig, _ := base64.StdEncoding.DecodeString(req.Header.Get(ProofHeader))
	ts := req.Header.Get(TimestampHeader)
	if ed25519.Verify(signer.PublicKey(), popMessage(req.Method, "/v1/resolve", ts), sig) {
		t.Fatal("proof bound to one path must not verify against another")
	}
}

func TestAttachProof_NoSignerIsNoOp(t *testing.T) {
	SetProofSigner(nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads/env", nil)
	AttachProof(req)
	if req.Header.Get(ProofHeader) != "" {
		t.Fatal("AttachProof with no signer must not set headers")
	}
}

func TestSetProofSigner_ActivatesProof(t *testing.T) {
	signer, _ := NewProofSigner()
	SetProofSigner(signer)
	t.Cleanup(func() { SetProofSigner(nil) })
	req := httptest.NewRequest(http.MethodPost, "/v1/identity", nil)
	AttachProof(req)
	verifyAttach(t, req, signer.PublicKey())
}

func TestNewProofSignerFromSeed_RoundTrip(t *testing.T) {
	signer, _ := NewProofSigner()
	seed := signer.priv.Seed()
	rebuilt, err := NewProofSignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if string(rebuilt.PublicKey()) != string(signer.PublicKey()) {
		t.Fatal("rebuilt signer must reproduce the same public key")
	}
	if _, err := NewProofSignerFromSeed(seed[:len(seed)-1]); err == nil {
		t.Fatal("a truncated seed must be rejected")
	}
}
