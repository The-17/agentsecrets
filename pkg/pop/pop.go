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
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// ProofHeader carries the detached Ed25519 signature. Must match the
	// resolver's server.popProofHeader.
	ProofHeader = "X-AS-PoP"
	// TimestampHeader carries the Unix-second timestamp the proof was signed
	// over. Must match the resolver's server.popTimestampHeader.
	TimestampHeader = "X-AS-PoP-TS"
	// SeedEnv carries the base64-encoded 32-byte Ed25519 private seed. It is a
	// SEPARATE secret from the workload token: a token leaked from a log is
	// useless without this value. Never derive it from the token, because a
	// self-sufficient token makes proof-of-possession theatre.
	SeedEnv = "AGENTSECRETS_POP_SEED"
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
// seed. This is the key-transport seam: the seed is generated once at agent
// create, shown once, and injected into the workload as SeedEnv. It is never
// embedded in the token, so a token leaked from a log is useless alone.
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

// Seed returns a copy of the 32-byte private seed. This is the value shown once
// at agent creation and injected into the workload as SeedEnv. It never travels
// inside the token.
func (s *ProofSigner) Seed() []byte {
	seed := s.priv.Seed()
	out := make([]byte, len(seed))
	copy(out, seed)
	return out
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
// to clear it. It is called from commands.Execute via LoadSignerFromEnvironment,
// which reads SeedEnv before any resolver call, so proofs are active whenever the
// seed is present.
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

// LoadSignerFromEnvironment installs the process-wide proof signer from SeedEnv.
// An absent variable is a legitimate no-PoP state: every pre-PoP token keeps
// working. A present but malformed value fails closed. Signing with the wrong
// key would only produce proofs the resolver rejects, so refusing to start is
// louder and cheaper than a string of opaque 401s.
func LoadSignerFromEnvironment() error {
	raw := strings.TrimSpace(os.Getenv(SeedEnv))
	if raw == "" {
		return nil
	}
	seed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return fmt.Errorf("%s is not valid base64: %w", SeedEnv, err)
	}
	signer, err := NewProofSignerFromSeed(seed)
	if err != nil {
		return fmt.Errorf("%s: %w", SeedEnv, err)
	}
	SetProofSigner(signer)
	return nil
}
