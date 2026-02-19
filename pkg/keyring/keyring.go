// Package keyring handles secure storage of cryptographic keys.
//
// This mirrors the Python SecretsCLI's CredentialsManager keypair methods.
// On macOS it uses Keychain, on Windows it uses Credential Manager.
// On Linux/WSL (where D-Bus Secret Service is typically unavailable),
// it falls back to file-based storage in ~/.agentsecrets/keyring.json.
//
// Service name: "AgentSecrets"
// Key naming: "{email}_private_key", "{email}_public_key"
package keyring

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	gokeyring "github.com/zalando/go-keyring"
)

const serviceName = "AgentSecrets"

// useFileBackend is true when the OS keyring is unavailable (WSL, headless Linux, etc.)
var useFileBackend bool

func init() {
	// On Linux, test if the keyring actually works. If not, fall back to file storage.
	// macOS and Windows have reliable keyring support.
	if runtime.GOOS == "linux" {
		// Try a test write/read/delete to see if keyring works
		testKey := "__agentsecrets_keyring_test__"
		err := gokeyring.Set(serviceName, testKey, "test")
		if err != nil {
			useFileBackend = true
		} else {
			_ = gokeyring.Delete(serviceName, testKey)
		}
	}
}

// StoreKeypair saves both private and public keys.
// Uses OS keychain when available, falls back to file on Linux/WSL.
func StoreKeypair(email string, privateKey, publicKey []byte) error {
	privB64 := base64.StdEncoding.EncodeToString(privateKey)
	pubB64 := base64.StdEncoding.EncodeToString(publicKey)

	if useFileBackend {
		return fileSet(email, privB64, pubB64)
	}

	if err := gokeyring.Set(serviceName, email+"_private_key", privB64); err != nil {
		return fmt.Errorf("failed to store private key: %w", err)
	}
	if err := gokeyring.Set(serviceName, email+"_public_key", pubB64); err != nil {
		return fmt.Errorf("failed to store public key: %w", err)
	}
	return nil
}

// GetPrivateKey retrieves the user's private key.
func GetPrivateKey(email string) ([]byte, error) {
	if useFileBackend {
		return fileGetKey(email, "private")
	}
	encoded, err := gokeyring.Get(serviceName, email+"_private_key")
	if err != nil {
		return nil, fmt.Errorf("private key not found in keychain: %w", err)
	}
	return base64.StdEncoding.DecodeString(encoded)
}

// GetPublicKey retrieves the user's public key.
func GetPublicKey(email string) ([]byte, error) {
	if useFileBackend {
		return fileGetKey(email, "public")
	}
	encoded, err := gokeyring.Get(serviceName, email+"_public_key")
	if err != nil {
		return nil, fmt.Errorf("public key not found in keychain: %w", err)
	}
	return base64.StdEncoding.DecodeString(encoded)
}

// DeleteKeypair removes both keys (used during logout).
func DeleteKeypair(email string) error {
	if useFileBackend {
		return fileDelete(email)
	}
	_ = gokeyring.Delete(serviceName, email+"_private_key")
	_ = gokeyring.Delete(serviceName, email+"_public_key")
	return nil
}

// --- File-based fallback for Linux/WSL ---

// keyringFile stores keys as a JSON map: { "email": { "private": "b64", "public": "b64" } }
type keyEntry struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

func keyringFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".agentsecrets")
	_ = os.MkdirAll(dir, 0700)
	return filepath.Join(dir, "keyring.json"), nil
}

func loadKeyringFile() (map[string]keyEntry, error) {
	path, err := keyringFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]keyEntry), nil
		}
		return nil, err
	}
	var entries map[string]keyEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return make(map[string]keyEntry), nil
	}
	return entries, nil
}

func saveKeyringFile(entries map[string]keyEntry) error {
	path, err := keyringFilePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600) // Restrictive permissions
}

func fileSet(email, privB64, pubB64 string) error {
	entries, err := loadKeyringFile()
	if err != nil {
		return fmt.Errorf("failed to load keyring file: %w", err)
	}
	entries[email] = keyEntry{Private: privB64, Public: pubB64}
	if err := saveKeyringFile(entries); err != nil {
		return fmt.Errorf("failed to save keyring file: %w", err)
	}
	return nil
}

func fileGetKey(email, keyType string) ([]byte, error) {
	entries, err := loadKeyringFile()
	if err != nil {
		return nil, err
	}
	entry, ok := entries[email]
	if !ok {
		return nil, fmt.Errorf("no keys found for %s", email)
	}
	var encoded string
	if keyType == "private" {
		encoded = entry.Private
	} else {
		encoded = entry.Public
	}
	if encoded == "" {
		return nil, fmt.Errorf("%s key not found for %s", keyType, email)
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func fileDelete(email string) error {
	entries, err := loadKeyringFile()
	if err != nil {
		return nil
	}
	delete(entries, email)
	return saveKeyringFile(entries)
}
