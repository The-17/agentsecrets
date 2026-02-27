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
	"strings"

	gokeyring "github.com/zalando/go-keyring"
)

const serviceName = "AgentSecrets"

// useFileBackend is true when the OS keyring is unavailable (WSL, headless Linux, etc.)
var useFileBackend bool

func init() {
	// On Linux, test if the keyring actually works. If not, fall back to file storage.
	// macOS and Windows have reliable keyring support.
	if runtime.GOOS == "linux" {
		// WSL specifically often hangs on dbus-based keyring calls if not set up correctly.
		if os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("DISPLAY") == "" {
			useFileBackend = true
			return
		}

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
	path := filepath.Join(home, ".agentsecrets", "keyring.json")
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	return path, nil
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

	encoded := entry.Public
	if keyType == "private" {
		encoded = entry.Private
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

// --- Individual Secret Storage (for Proxy support) ---

func secretKeyName(projectID, key string) string {
	return fmt.Sprintf("Secret_%s_%s", projectID, key)
}

// SetSecret stores a decrypted secret in the keyring and updates the project's key index.
func SetSecret(projectID, key, value string) error {
	name := secretKeyName(projectID, key)
	if useFileBackend {
		// Base64-encode before storing so fileGetKey's decode round-trips correctly.
		encoded := base64.StdEncoding.EncodeToString([]byte(value))
		if err := fileSet(name, encoded, ""); err != nil {
			return err
		}
	} else {
		if err := gokeyring.Set(serviceName, name, value); err != nil {
			return fmt.Errorf("set secret %s: %w", name, err)
		}
	}
	return addKeyToIndex(projectID, key)
}

// GetSecret retrieves a secret from the keyring.
func GetSecret(projectID, key string) (string, error) {
	name := secretKeyName(projectID, key)
	if useFileBackend {
		val, err := fileGetKey(name, "private")
		if err != nil {
			return "", fmt.Errorf("get secret: %w", err)
		}
		return string(val), nil
	}

	val, err := gokeyring.Get(serviceName, name)
	if err != nil {
		return "", fmt.Errorf("get secret: %w", err)
	}
	return val, nil
}

// DeleteSecret removes a secret from the keyring and its index.
func DeleteSecret(projectID, key string) error {
	name := secretKeyName(projectID, key)
	if useFileBackend {
		if err := fileDelete(name); err != nil {
			return err
		}
	} else {
		_ = gokeyring.Delete(serviceName, name)
	}
	return removeKeyFromIndex(projectID, key)
}

// --- Key Index Management ---
// We maintain a comma-separated list of keys per project so we can iterate them 
// since go-keyring lacks a list/iterate feature.

func projectIndexName(projectID string) string {
	return fmt.Sprintf("ProjectKeys_%s", projectID)
}

func getProjectKeys(projectID string) []string {
	var val string
	name := projectIndexName(projectID)

	if useFileBackend {
		if v, err := fileGetKey(name, "private"); err == nil {
			val = string(v)
		}
	} else {
		if v, err := gokeyring.Get(serviceName, name); err == nil {
			val = v
		}
	}

	if val == "" {
		return []string{}
	}
	return strings.Split(val, ",")
}

func saveProjectKeys(projectID string, keys []string) error {
	name := projectIndexName(projectID)
	val := strings.Join(keys, ",")

	if useFileBackend {
		encoded := base64.StdEncoding.EncodeToString([]byte(val))
		return fileSet(name, encoded, "")
	}
	return gokeyring.Set(serviceName, name, val)
}

func addKeyToIndex(projectID, key string) error {
	keys := getProjectKeys(projectID)
	for _, k := range keys {
		if k == key {
			return nil // Already exists
		}
	}
	keys = append(keys, key)
	return saveProjectKeys(projectID, keys)
}

func removeKeyFromIndex(projectID, key string) error {
	keys := getProjectKeys(projectID)
	var newKeys []string
	for _, k := range keys {
		if k != key {
			newKeys = append(newKeys, k)
		}
	}
	return saveProjectKeys(projectID, newKeys)
}

// GetAllProjectSecrets returns all secrets mapped for a specific project from the keyring.
func GetAllProjectSecrets(projectID string) (map[string]string, error) {
	keys := getProjectKeys(projectID)
	res := make(map[string]string)

	for _, k := range keys {
		if val, err := GetSecret(projectID, k); err == nil {
			res[k] = val
		}
	}
	return res, nil
}

