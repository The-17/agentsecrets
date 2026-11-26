package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/The-17/agentsecrets/pkg/keychainauth"
	"golang.org/x/crypto/argon2"
)

const (
	passwordVerifierService = "AgentSecrets"
	passwordVerifierTarget  = "local_password_verifier"
	passwordVerifierSaltLen = 16
	passwordVerifierTime    = 3
	passwordVerifierMemory  = 64 * 1024
	passwordVerifierThreads = 4
	passwordVerifierKeyLen  = 32
)

type passwordVerifier struct {
	Version int    `json:"v"`
	Salt    string `json:"s"`
	Hash    string `json:"h"`
}

// StorePasswordVerifier replaces the local password gate with a fresh salted
// Argon2id record held by keychain-auth. The email is not part of the verifier
// and nothing is written to config.json.
func StorePasswordVerifier(password string) error {
	salt := make([]byte, passwordVerifierSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("password verifier: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, passwordVerifierTime, passwordVerifierMemory, passwordVerifierThreads, passwordVerifierKeyLen)
	record := passwordVerifier{
		Version: 1,
		Salt:    base64.RawStdEncoding.EncodeToString(salt),
		Hash:    base64.RawStdEncoding.EncodeToString(key),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("password verifier: encode: %w", err)
	}
	if err := keychainauth.Write(passwordVerifierService, passwordVerifierTarget, string(encoded)); err != nil {
		return fmt.Errorf("password verifier: keychain-auth write: %w", err)
	}
	return nil
}

// VerifyPasswordLocally checks a typed password against the stored verifier.
// A missing, malformed, or unknown-format record fails closed.
func VerifyPasswordLocally(password string) (bool, error) {
	raw, err := keychainauth.Read(passwordVerifierService, passwordVerifierTarget)
	if err != nil {
		return false, fmt.Errorf("password verifier: keychain-auth read: %w", err)
	}
	if raw == "" {
		return false, nil
	}

	var record passwordVerifier
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		return false, fmt.Errorf("password verifier: malformed record: %w", err)
	}
	if record.Version != 1 {
		return false, fmt.Errorf("password verifier: unsupported version %d", record.Version)
	}
	salt, err := base64.RawStdEncoding.DecodeString(record.Salt)
	if err != nil || len(salt) != passwordVerifierSaltLen {
		return false, fmt.Errorf("password verifier: malformed salt")
	}
	want, err := base64.RawStdEncoding.DecodeString(record.Hash)
	if err != nil || len(want) != passwordVerifierKeyLen {
		return false, fmt.Errorf("password verifier: malformed hash")
	}

	got := argon2.IDKey([]byte(password), salt, passwordVerifierTime, passwordVerifierMemory, passwordVerifierThreads, passwordVerifierKeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// HasPasswordVerifier reports whether this machine can answer a local password
// check. Callers use it to explain why a sensitive command is unavailable.
func HasPasswordVerifier() bool {
	raw, err := keychainauth.Read(passwordVerifierService, passwordVerifierTarget)
	return err == nil && raw != ""
}
