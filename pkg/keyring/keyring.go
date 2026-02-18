// Package keyring handles secure storage of cryptographic keys in the OS keychain.
//
// This mirrors the Python SecretsCLI's CredentialsManager keypair methods.
// On macOS it uses Keychain, on Windows it uses Credential Manager,
// on Linux it uses Secret Service (or plaintext fallback).
//
// Service name: "AgentSecrets"
// Key naming: "{email}_private_key", "{email}_public_key"
package keyring

import (
	"encoding/base64"
	"fmt"

	gokeyring "github.com/zalando/go-keyring"
)

const serviceName = "AgentSecrets"

// StoreKeypair saves both private and public keys to the OS keychain.
// Keys are base64-encoded before storage.
func StoreKeypair(email string, privateKey, publicKey []byte) error {
	privB64 := base64.StdEncoding.EncodeToString(privateKey)
	pubB64 := base64.StdEncoding.EncodeToString(publicKey)

	if err := gokeyring.Set(serviceName, email+"_private_key", privB64); err != nil {
		return fmt.Errorf("failed to store private key: %w", err)
	}

	if err := gokeyring.Set(serviceName, email+"_public_key", pubB64); err != nil {
		return fmt.Errorf("failed to store public key: %w", err)
	}

	return nil
}

// GetPrivateKey retrieves the user's private key from the OS keychain.
func GetPrivateKey(email string) ([]byte, error) {
	encoded, err := gokeyring.Get(serviceName, email+"_private_key")
	if err != nil {
		return nil, fmt.Errorf("private key not found in keychain: %w", err)
	}
	return base64.StdEncoding.DecodeString(encoded)
}

// GetPublicKey retrieves the user's public key from the OS keychain.
func GetPublicKey(email string) ([]byte, error) {
	encoded, err := gokeyring.Get(serviceName, email+"_public_key")
	if err != nil {
		return nil, fmt.Errorf("public key not found in keychain: %w", err)
	}
	return base64.StdEncoding.DecodeString(encoded)
}

// DeleteKeypair removes both keys from the OS keychain (used during logout).
func DeleteKeypair(email string) error {
	// Ignore errors — keys may not exist
	_ = gokeyring.Delete(serviceName, email+"_private_key")
	_ = gokeyring.Delete(serviceName, email+"_public_key")
	return nil
}
