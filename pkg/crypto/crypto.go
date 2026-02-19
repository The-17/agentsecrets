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
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/box"
)

// NonceSize is the standard nonce size for AES-256-GCM (12 bytes)
const NonceSize = 12

// KeySize is the size of AES-256-GCM keys and X25519 keys (32 bytes)
const KeySize = 32

// SaltSize is the size of the Argon2id salt (32 bytes)
const SaltSize = 32

// Argon2id parameters (OWASP recommended)
const (
	argonTime    = 3      // iterations
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	argonKeyLen  = 32
)

// UserKeys holds the output of SetupUser — everything needed to register a new account.
type UserKeys struct {
	PrivateKey          []byte // Raw 32-byte private key (stored in keyring)
	PublicKey           []byte // Raw 32-byte public key
	EncryptedPrivateKey string // Base64-encoded AES-256-GCM ciphertext of private key
	Salt                string // Hex-encoded Argon2id salt
}

// SetupUser generates a new keypair and encrypts the private key with the user's password.
// This is called during account creation (init command).
//
// Flow:
//  1. Generate X25519 keypair
//  2. Generate random salt
//  3. Derive encryption key from password using Argon2id
//  4. Encrypt private key with AES-256-GCM using derived key
func SetupUser(password string) (*UserKeys, error) {
	// Generate keypair
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("setup_user: %w", err)
	}

	// Encrypt private key with password
	encryptedPrivateKey, salt, err := EncryptPrivateKey(privateKey, password)
	if err != nil {
		return nil, fmt.Errorf("setup_user: %w", err)
	}

	return &UserKeys{
		PrivateKey:          privateKey,
		PublicKey:           publicKey,
		EncryptedPrivateKey: encryptedPrivateKey,
		Salt:                salt,
	}, nil
}

// DeriveKeyFromPassword derives a 32-byte encryption key from a password using Argon2id.
func DeriveKeyFromPassword(password, saltHex string) ([]byte, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("invalid salt hex: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return key, nil
}

// EncryptPrivateKey encrypts a private key with a password-derived key.
// Returns (base64 ciphertext, hex salt).
func EncryptPrivateKey(privateKey []byte, password string) (ciphertextB64, saltHex string, err error) {
	// Generate random salt
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", "", fmt.Errorf("failed to generate salt: %w", err)
	}
	saltHex = hex.EncodeToString(salt)

	// Derive key from password
	derivedKey, err := DeriveKeyFromPassword(password, saltHex)
	if err != nil {
		return "", "", err
	}

	// Encrypt private key with AES-256-GCM
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("failed to create GCM: %w", err)
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal: nonce is prepended to ciphertext for storage
	ciphertext := aesGCM.Seal(nonce, nonce, privateKey, nil)

	return base64.StdEncoding.EncodeToString(ciphertext), saltHex, nil
}

// DecryptPrivateKey decrypts a private key using the user's password.
// This is called during login to recover the private key from the server's encrypted copy.
func DecryptPrivateKey(encryptedB64, password, saltHex string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted private key: %w", err)
	}

	derivedKey, err := DeriveKeyFromPassword(password, saltHex)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce (prepended during encryption)
	nonce, ciphertextBody := ciphertext[:nonceSize], ciphertext[nonceSize:]

	privateKey, err := aesGCM.Open(nil, nonce, ciphertextBody, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key (wrong password?): %w", err)
	}

	return privateKey, nil
}

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
