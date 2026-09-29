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

const NonceSize = 12
const KeySize = 32
const SaltSize = 32
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
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
	salt, err := randomBytes(SaltSize)
	if err != nil {
		return "", "", err
	}
	saltHex = hex.EncodeToString(salt)

	// Derive key from password
	derivedKey, err := DeriveKeyFromPassword(password, saltHex)
	if err != nil {
		return "", "", err
	}

	// Encrypt private key with AES-256-GCM
	aesGCM, err := newGCM(derivedKey)
	if err != nil {
		return "", "", err
	}
	nonce, err := randomBytes(aesGCM.NonceSize())
	if err != nil {
		return "", "", err
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

	aesGCM, err := newGCM(derivedKey)
	if err != nil {
		return nil, err
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
	return randomBytes(KeySize)
}

// GeneratePassword creates a cryptographically random password of the given
// byte length, base64url-encoded without padding (suitable for API keys and
// database passwords rotated via `secrets rotate --generate`).
func GeneratePassword(byteLength int) (string, error) {
	if byteLength <= 0 || byteLength > 256 {
		return "", fmt.Errorf("password length must be between 1 and 256 bytes")
	}
	raw, err := randomBytes(byteLength)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// EncryptSecret encrypts a plaintext secret with a workspace key using AES-256-GCM.
// The nonce is prepended to the ciphertext and returned as a single base64-encoded string.
func EncryptSecret(plaintext string, workspaceKey []byte) (string, error) {
	aesGCM, err := newGCM(workspaceKey)
	if err != nil {
		return "", err
	}

	// Generate random nonce
	nonce, err := randomBytes(aesGCM.NonceSize())
	if err != nil {
		return "", err
	}

	// Encrypt and prepend nonce
	// Seal(dst, nonce, plaintext, additionalData)
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptSecret decrypts a base64-encoded ciphertext (with prepended nonce) using AES-256-GCM.
func DecryptSecret(encryptedB64 string, workspaceKey []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	aesGCM, err := newGCM(workspaceKey)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext body
	nonce, ciphertextBody := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertextBody, nil)
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

// B64Encode is a shorthand for base64 standard encoding.
func B64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// B64Decode decodes a base64 standard-encoded string, wrapping any error with
// the given context message.
func B64Decode(s, context string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", context, err)
	}
	return b, nil
}

// --- Internal Helpers ---

func randomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return gcm, nil
}
