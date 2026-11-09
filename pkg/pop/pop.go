// Package pop implements the client half of DPoP-style proof-of-possession
// (cnf/jkt) for workload requests to the Go resolver. It is a leaf package:
// stdlib only, so every transport package (pkg/api, pkg/gateway) can import it
// without creating an import cycle.
//
// This is a dormant foundation. The resolver requires a proof only when a token
// carries a confirmation key, and the control plane does not mint one yet. Key
// transport (how the private key reaches the workload that holds the token) is
// an open ADR decision and is deliberately NOT decided here. AttachProof is a
// no-op until a signer is installed with SetProofSigner, which happens only once
// that decision is made. Tokens minted today are entirely unaffected.
package pop

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const (
	// ProofHeader carries the detached Ed25519 signature. Must match the
	// resolver's server.popProofHeader.
	ProofHeader = "X-AS-PoP"
	// TimestampHeader carries the Unix-second timestamp the proof was signed
	// over. Must match the resolver's server.popTimestampHeader.
	TimestampHeader = "X-AS-PoP-TS"
)

// Cross-repo golden vector. These bytes are duplicated verbatim in the cloud
// resolver's internal/server/pop_test.go. Ed25519 signing is deterministic, so
// one fixed seed + method + path + timestamp yields one signature. If either
// side changes the signed message or header names, its own test fails against
// these constants and the drift cannot ship silently.
const (
	goldenSeed      = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	goldenPublicKey = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
	goldenTimestamp = "1700000000"
	goldenMethod    = "POST"
	goldenPath      = "/v1/identity"
	goldenSignature = "wEmglnn7tt0fp0q6ZKGgDmsNIYA5V5qrTnUrzxcHy/rEQ/wLmfvbd5MxzzlMxI63ihuW4liDO6FJ6z4uR1UXBQ=="
)

// ProofSigner holds the private half of a proof-of-possession keypair. The
// matching public key is bound to a workload token at mint time; the private
// key never leaves this process.
type ProofSigner struct {
	priv ed25519.PrivateKey
}

// NewProofSigner generates a fresh proof-of-possession keypair.
func NewProofSigner() (*ProofSigner, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ProofSigner{priv: priv}, nil
}

// NewProofSignerFromSeed rebuilds a signer from a persisted 32-byte Ed25519
// seed. This is the seam the (still-undecided) key-transport ADR will use: the
// seed's storage and delivery are deliberately out of scope here.
func NewProofSignerFromSeed(seed []byte) (*ProofSigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("proof seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return &ProofSigner{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// PublicKey returns the raw public key bytes to register as the token's cnf/jkt.
func (s *ProofSigner) PublicKey() []byte {
	return s.priv.Public().(ed25519.PublicKey)
}

// Attach signs the request (METHOD + URL.Path + current timestamp) and sets the
// proof headers. The message format MUST match the resolver's verification
// (server.popMessage): "METHOD\nPATH\nTIMESTAMP".
func (s *ProofSigner) Attach(req *http.Request) {
	s.attachAt(req, strconv.FormatInt(time.Now().Unix(), 10))
}

// attachAt is the deterministic seam used by the cross-repo golden-vector test.
// The wire contract is duplicated between this package and the cloud resolver,
// so a fixed vector pinned in both test suites is the only proof they agree.
func (s *ProofSigner) attachAt(req *http.Request, ts string) {
	msg := []byte(req.Method + "\n" + req.URL.Path + "\n" + ts)
	sig := ed25519.Sign(s.priv, msg)
	req.Header.Set(ProofHeader, base64.StdEncoding.EncodeToString(sig))
	req.Header.Set(TimestampHeader, ts)
}

var active *ProofSigner

// SetProofSigner installs the process-wide signer used by AttachProof. Pass nil
// to clear it. This is the activation point for the key-transport decision; it
// is not called by any production path yet, so proofs are currently dormant.
func SetProofSigner(s *ProofSigner) {
	active = s
}

// AttachProof signs an outgoing resolver request when a signer is installed.
// It is a no-op otherwise, which keeps every pre-PoP token working unchanged.
func AttachProof(req *http.Request) {
	if active != nil {
		active.Attach(req)
	}
}
