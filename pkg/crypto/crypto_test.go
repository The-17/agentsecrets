package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDeriveKeyFromPassword(t *testing.T) {
	password := "super-secret-password"
	salt := "0102030405060708090a0b0c0d0e0f10"

	key1, err := DeriveKeyFromPassword(password, salt)
	if err != nil {
		t.Fatalf("DeriveKeyFromPassword failed: %v", err)
	}

	if len(key1) != KeySize {
		t.Errorf("Expected key length %d, got %d", KeySize, len(key1))
	}

	// Verify idempotency
	key2, err := DeriveKeyFromPassword(password, salt)
	if err != nil {
		t.Fatalf("DeriveKeyFromPassword failed on second call: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("Key derivation is not deterministic (different keys for same password/salt)")
	}

	// Verify different salt produces different key
	salt2 := "100e0d0c0b0a09080706050403020100"
	key3, err := DeriveKeyFromPassword(password, salt2)
	if err != nil {
		t.Fatalf("DeriveKeyFromPassword failed with second salt: %v", err)
	}

	if bytes.Equal(key1, key3) {
		t.Error("Different salts produced the same key")
	}

	// Verify different password produces different key
	key4, err := DeriveKeyFromPassword("wrong-password", salt)
	if err != nil {
		t.Fatalf("DeriveKeyFromPassword failed with second password: %v", err)
	}

	if bytes.Equal(key1, key4) {
		t.Error("Different passwords produced the same key")
	}
}

func TestPrivateKeyEncryptionRoundtrip(t *testing.T) {
	password := "p@ssword123"
	originalKey := []byte("this-is-a-32-byte-private-key-000") // 32 bytes

	// Encrypt
	encB64, salt, err := EncryptPrivateKey(originalKey, password)
	if err != nil {
		t.Fatalf("EncryptPrivateKey failed: %v", err)
	}

	if encB64 == "" || salt == "" {
		t.Fatal("Encryption returned empty ciphertext or salt")
	}

	// Decrypt
	decrypted, err := DecryptPrivateKey(encB64, password, salt)
	if err != nil {
		t.Fatalf("DecryptPrivateKey failed: %v", err)
	}

	if !bytes.Equal(originalKey, decrypted) {
		t.Error("Decrypted key does not match original key")
	}

	// Verify decryption fails with wrong password
	_, err = DecryptPrivateKey(encB64, "wrong-password", salt)
	if err == nil {
		t.Error("Decryption should have failed with incorrect password")
	}
}

func TestWorkspaceSecretEncryptionRoundtrip(t *testing.T) {
	wsKey := make([]byte, KeySize)
	for i := range wsKey {
		wsKey[i] = byte(i)
	}

	secretValue := "my-database-password-123!"

	// Encrypt
	encrypted, err := EncryptSecret(secretValue, wsKey)
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}

	if encrypted == "" {
		t.Fatal("Encrypted secret is empty")
	}

	// Decrypt
	decrypted, err := DecryptSecret(encrypted, wsKey)
	if err != nil {
		t.Fatalf("DecryptSecret failed: %v", err)
	}

	if decrypted != secretValue {
		t.Errorf("Decrypted value expected %q, got %q", secretValue, decrypted)
	}

	// Verify decryption fails with wrong workspace key
	wrongWsKey := make([]byte, KeySize)
	_, err = DecryptSecret(encrypted, wrongWsKey)
	if err == nil {
		t.Error("Decryption should have failed with incorrect workspace key")
	}
}

func TestSetupUser(t *testing.T) {
	password := "test-setup-pass"
	keys, err := SetupUser(password)
	if err != nil {
		t.Fatalf("SetupUser failed: %v", err)
	}

	if len(keys.PrivateKey) != 32 || len(keys.PublicKey) != 32 {
		t.Error("Invalid raw key lengths")
	}

	if keys.Salt == "" || keys.EncryptedPrivateKey == "" {
		t.Error("Missing salt or encrypted private key in SetupUser result")
	}

	// Verify we can decrypt the private key from the setup result
	decryptedPriv, err := DecryptPrivateKey(keys.EncryptedPrivateKey, password, keys.Salt)
	if err != nil {
		t.Fatalf("Failed to decrypt private key from SetupUser: %v", err)
	}

	if !bytes.Equal(keys.PrivateKey, decryptedPriv) {
		t.Error("Decrypted private key from setup does not match generated raw private key")
	}
}

func TestEncryptForUserRoundtrip(t *testing.T) {
	// Generate a recipient
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	workspaceKey := []byte("secret-workspace-key-32-bytes-!!") // 32 bytes

	// Encrypt for recipient
	encrypted, err := EncryptForUser(pub, workspaceKey)
	if err != nil {
		t.Fatalf("EncryptForUser failed: %v", err)
	}

	// Decrypt with recipient's private key
	decrypted, err := DecryptFromUser(priv, pub, encrypted)
	if err != nil {
		t.Fatalf("DecryptFromUser failed: %v", err)
	}

	if !bytes.Equal(workspaceKey, decrypted) {
		t.Error("Asymmetrically decrypted workspace key does not match original")
	}
}

func TestHexEncoding(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	encoded := hex.EncodeToString(data)
	if encoded != "deadbeef" {
		t.Errorf("Expected deadbeef, got %s", encoded)
	}

	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatalf("Hex decode failed: %v", err)
	}
	if !bytes.Equal(data, decoded) {
		t.Error("Hex roundtrip failed")
	}
}
