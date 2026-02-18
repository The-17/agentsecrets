// Package crypto handles all cryptographic operations for AgentSecrets.
//
// This mirrors the Python SecretsCLI's encryption.py but uses:
//   - AES-256-GCM instead of Fernet for symmetric encryption
//   - X25519 + NaCl SealedBox for asymmetric encryption (same as Python)
//   - Argon2id instead of PBKDF2-SHA256 for key derivation
//
// Key hierarchy:
//   Password → (Argon2id) → Password-Derived Key → decrypts Private Key
//   Private Key → (NaCl SealedBox) → decrypts Workspace Key
//   Workspace Key → (AES-256-GCM) → encrypts/decrypts Secrets
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

// NonceSize is the standard nonce size for AES-256-GCM (12 bytes)
const NonceSize = 12

// KeySize is the size of AES-256-GCM keys and X25519 keys (32 bytes)
const KeySize = 32

// GenerateKeypair creates a new X25519 keypair for asymmetric encryption.
// Returns (privateKey, publicKey) — both are 32 bytes.
func GenerateKeypair() (privateKey, publicKey []byte, err error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate keypair: %w", err)
	}
	return priv[:], pub[:], nil
}

// GenerateWorkspaceKey creates a random 32-byte key for AES-256-GCM encryption.
func GenerateWorkspaceKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate workspace key: %w", err)
	}
	return key, nil
}

// EncryptSecret encrypts a plaintext secret with a workspace key using AES-256-GCM.
// Returns (ciphertext, nonce) both base64-encoded.
func EncryptSecret(plaintext string, workspaceKey []byte) (ciphertextB64, nonceB64 string, err error) {
	block, err := aes.NewCipher(workspaceKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt (GCM appends the auth tag to the ciphertext)
	ciphertext := aesGCM.Seal(nil, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext),
		base64.StdEncoding.EncodeToString(nonce),
		nil
}

// DecryptSecret decrypts a base64-encoded ciphertext with a workspace key using AES-256-GCM.
func DecryptSecret(ciphertextB64, nonceB64 string, workspaceKey []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}

	block, err := aes.NewCipher(workspaceKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// EncryptForUser encrypts data using the recipient's X25519 public key (NaCl SealedBox).
// Used for encrypting workspace keys when inviting team members.
func EncryptForUser(recipientPublicKey, data []byte) ([]byte, error) {
	if len(recipientPublicKey) != KeySize {
		return nil, fmt.Errorf("invalid public key size: got %d, want %d", len(recipientPublicKey), KeySize)
	}

	var pubKey [KeySize]byte
	copy(pubKey[:], recipientPublicKey)

	encrypted, err := box.SealAnonymous(nil, data, &pubKey, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt for user: %w", err)
	}

	return encrypted, nil
}

// DecryptFromUser decrypts data that was encrypted with our public key (NaCl SealedBox).
// Used for decrypting workspace keys received from team invites.
func DecryptFromUser(privateKey, publicKey, encrypted []byte) ([]byte, error) {
	if len(privateKey) != KeySize || len(publicKey) != KeySize {
		return nil, fmt.Errorf("invalid key size")
	}

	var privKey, pubKey [KeySize]byte
	copy(privKey[:], privateKey)
	copy(pubKey[:], publicKey)

	decrypted, ok := box.OpenAnonymous(nil, encrypted, &pubKey, &privKey)
	if !ok {
		return nil, fmt.Errorf("failed to decrypt: authentication failed")
	}

	return decrypted, nil
}
