// Package opaque is the client half of AgentSecrets' OPAQUE (RFC 9807)
// password-authenticated key exchange.
//
// The server never sees the password and never performs OPAQUE math itself: it
// proxies to a sidecar built from this same library. Both ends must therefore
// share an implementation, which is why the client pins the capability and
// refuses to fall back when a server says the account has no password factor.
package opaque

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/bytemare/opaque"
)

// Capability is the minimum server capability this client requires.
const Capability = "opaque_v1"

// AuthState is what the CLI keeps locally alongside the vault: the credential
// id and the registration record blob the server stores.
type AuthState struct {
	CredentialID string
	Record       []byte
}

// ErrPasswordLoginDisabled means the account is enrolled. The caller must
// surface this as "use OPAQUE login" and must not retry with a password.
var ErrPasswordLoginDisabled = fmt.Errorf("password login is disabled for this account")

func encodeB64(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

func decodeB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}

// RegisterStart produces the first registration message the server forwards to
// its sidecar.
func RegisterStart(password string) (*opaque.Client, []byte, error) {
	conf := opaque.DefaultConfiguration()
	client, err := conf.Client()
	if err != nil {
		return nil, nil, fmt.Errorf("opaque: client init: %w", err)
	}
	req, err := client.RegistrationInit([]byte(password))
	if err != nil {
		return nil, nil, fmt.Errorf("opaque: registration init: %w", err)
	}
	return client, req.Serialize(), nil
}

// RegisterFinish completes registration from the server's reg_response and
// returns the record the client must store on the server.
func RegisterFinish(client *opaque.Client, regResponse []byte, credentialID string) ([]byte, error) {
	conf := opaque.DefaultConfiguration()
	dser, err := conf.Deserializer()
	if err != nil {
		return nil, fmt.Errorf("opaque: deserializer: %w", err)
	}
	parsed, err := dser.RegistrationResponse(regResponse)
	if err != nil {
		return nil, fmt.Errorf("opaque: parse registration response: %w", err)
	}
	record, _, err := client.RegistrationFinalize(parsed, []byte(credentialID), nil)
	if err != nil {
		return nil, fmt.Errorf("opaque: registration finalize: %w", err)
	}
	client.ClearState()
	return record.Serialize(), nil
}

// LoginStart produces KE1, which the server forwards to its sidecar alongside
// the stored record.
func LoginStart(password string) (*opaque.Client, []byte, error) {
	conf := opaque.DefaultConfiguration()
	client, err := conf.Client()
	if err != nil {
		return nil, nil, fmt.Errorf("opaque: client init: %w", err)
	}
	ke1, err := client.GenerateKE1([]byte(password))
	if err != nil {
		return nil, nil, fmt.Errorf("opaque: generate ke1: %w", err)
	}
	return client, ke1.Serialize(), nil
}

// LoginFinish completes the exchange. A wrong password fails here, before any
// session is acknowledged.
func LoginFinish(client *opaque.Client, ke2, credentialID string) (ke3 []byte, sessionKey []byte, err error) {
	conf := opaque.DefaultConfiguration()
	dser, err := conf.Deserializer()
	if err != nil {
		return nil, nil, fmt.Errorf("opaque: deserializer: %w", err)
	}
	raw, err := decodeB64(ke2)
	if err != nil {
		return nil, nil, fmt.Errorf("opaque: decode ke2: %w", err)
	}
	parsed, err := dser.KE2(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("opaque: parse ke2: %w", err)
	}
	k3, key, _, err := client.GenerateKE3(parsed, []byte(credentialID), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("opaque: login failed: %w", err)
	}
	client.ClearState()
	return k3.Serialize(), key, nil
}

// EncodeB64 exposes the encoding used on the wire so callers stay consistent.
func EncodeB64(raw []byte) string { return encodeB64(raw) }

// DecodeB64 is the inverse of EncodeB64 for server responses.
func DecodeB64(s string) ([]byte, error) { return decodeB64(s) }
