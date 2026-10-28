package sidecar

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/bytemare/opaque"
)

// OPAQUE server key material: a long-term AKE private key, its public key, and
// the OPRF global seed. All three are required and must never change for the
// lifetime of the deployment, because a registration record is bound to them.
//
// The wire form is `sk:pk:oprf`, each field standard base64. The library's own
// ServerKeyMaterial.Encode/Hex do not round trip when Identity is empty
// (DecodeLongVector rejects zero-length vectors), so this format is explicit
// rather than borrowed. Identity stays empty on purpose: the client binds the
// server identity to the public key by default, and a second, distinct identity
// string would have to be threaded through every client call for no gain.

const keyMaterialFields = 3

func FormatKeyMaterial(skm *opaque.ServerKeyMaterial) (string, error) {
	if skm == nil || skm.PrivateKey == nil {
		return "", fmt.Errorf("key material is empty")
	}
	public := skm.PublicKeyBytes
	seed := skm.OPRFGlobalSeed
	if len(public) == 0 || len(seed) == 0 {
		return "", fmt.Errorf("key material is missing the public key or the OPRF seed")
	}
	return strings.Join([]string{
		base64.StdEncoding.EncodeToString(skm.PrivateKey.Encode()),
		base64.StdEncoding.EncodeToString(public),
		base64.StdEncoding.EncodeToString(seed),
	}, ":"), nil
}

func GenerateKeyMaterial(conf *opaque.Configuration) (*opaque.ServerKeyMaterial, error) {
	secret, public := conf.KeyGen()
	if secret == nil || public == nil {
		return nil, fmt.Errorf("key generation failed")
	}
	return &opaque.ServerKeyMaterial{
		PrivateKey:     secret,
		PublicKeyBytes: public.Encode(),
		OPRFGlobalSeed: conf.GenerateOPRFSeed(),
	}, nil
}

// parseKeyMaterial decodes and validates the deployment key material. It fails
// closed: a malformed value must stop the process, because starting with
// partial or regenerated keys strands every enrolled account.
func parseKeyMaterial(conf *opaque.Configuration, encoded string) (*opaque.ServerKeyMaterial, error) {
	parts := strings.Split(strings.TrimSpace(encoded), ":")
	if len(parts) != keyMaterialFields {
		return nil, fmt.Errorf("expected %d colon-separated base64 fields, got %d", keyMaterialFields, len(parts))
	}

	fields := make([][]byte, keyMaterialFields)
	for i, part := range parts {
		raw, err := base64.StdEncoding.DecodeString(part)
		if err != nil {
			return nil, fmt.Errorf("field %d is not valid base64: %w", i, err)
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("field %d is empty", i)
		}
		fields[i] = raw
	}

	dser, err := conf.Deserializer()
	if err != nil {
		return nil, err
	}
	private, err := dser.DecodePrivateKey(fields[0])
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	if _, err := dser.DecodePublicKey(fields[1]); err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}

	skm := &opaque.ServerKeyMaterial{
		PrivateKey:     private,
		PublicKeyBytes: fields[1],
		OPRFGlobalSeed: fields[2],
	}

	// SetKeyMaterial is the authoritative check: it verifies the public key
	// matches the private key and that the OPRF seed has the right length.
	server, err := conf.Server()
	if err != nil {
		return nil, err
	}
	if err := server.SetKeyMaterial(skm); err != nil {
		return nil, fmt.Errorf("key material is inconsistent: %w", err)
	}
	return skm, nil
}
