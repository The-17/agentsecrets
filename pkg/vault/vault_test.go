package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/The-17/agentsecrets/pkg/crypto"
)

func newTestVault(t *testing.T) (*Vault, *Material, []byte, string) {
	t.Helper()
	privateKey, _, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	v, material, err := Create("user-1", "correct horse battery staple", privateKey)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return v, material, privateKey, "user-1"
}

func TestCreateUnlocksWithEveryFactor(t *testing.T) {
	v, material, privateKey, userID := newTestVault(t)

	passwordVK, err := v.UnlockWithPassword(userID, "correct horse battery staple")
	if err != nil {
		t.Fatalf("password unlock: %v", err)
	}
	if !bytes.Equal(passwordVK, material.VK) {
		t.Fatal("password unlock returned a different VK")
	}

	recoveryVK, err := v.UnlockWithRecoveryKey(userID, EncodeRecoveryKey(material.RecoveryKey))
	if err != nil {
		t.Fatalf("recovery unlock: %v", err)
	}
	if !bytes.Equal(recoveryVK, material.VK) {
		t.Fatal("recovery unlock returned a different VK")
	}

	decrypted, err := v.PrivateKey(userID, recoveryVK)
	if err != nil {
		t.Fatalf("open private key: %v", err)
	}
	if !bytes.Equal(decrypted, privateKey) {
		t.Fatal("private key mismatch")
	}
}

func TestWrongPasswordRejected(t *testing.T) {
	v, _, _, userID := newTestVault(t)
	if _, err := v.UnlockWithPassword(userID, "wrong password"); err == nil {
		t.Fatal("wrong password accepted")
	}
}

func TestTamperedCiphertextRejected(t *testing.T) {
	v, _, _, userID := newTestVault(t)
	raw, err := base64.StdEncoding.DecodeString(v.Envelopes[0].Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 1
	v.Envelopes[0].Ciphertext = base64.StdEncoding.EncodeToString(raw)
	if _, err := v.UnlockWithPassword(userID, "correct horse battery staple"); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestCrossAccountAADRejected(t *testing.T) {
	v, _, _, _ := newTestVault(t)
	if _, err := v.UnlockWithPassword("user-2", "correct horse battery staple"); err == nil {
		t.Fatal("cross-account unlock accepted")
	}
}

func TestPasskeyEnvelope(t *testing.T) {
	v, material, _, userID := newTestVault(t)
	prf := bytes.Repeat([]byte{0x42}, KeySize)
	id, err := v.AddPasskeyEnvelope(userID, material.VK, prf, "cred-1")
	if err != nil {
		t.Fatalf("add passkey: %v", err)
	}
	if id == "" {
		t.Fatal("empty passkey envelope id")
	}
	got, err := v.UnlockWithPasskey(userID, prf, "cred-1")
	if err != nil {
		t.Fatalf("passkey unlock: %v", err)
	}
	if !bytes.Equal(got, material.VK) {
		t.Fatal("passkey returned a different VK")
	}
	if _, err := v.UnlockWithPasskey(userID, prf, "cred-2"); err == nil {
		t.Fatal("wrong credential id accepted")
	}
	if _, err := v.UnlockWithPasskey(userID, bytes.Repeat([]byte{0x43}, KeySize), "cred-1"); err == nil {
		t.Fatal("wrong PRF accepted")
	}
}

func TestRecoveryKeyEncoding(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, KeySize)
	encoded := EncodeRecoveryKey(key)
	decoded, err := DecodeRecoveryKey(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(decoded, key) {
		t.Fatal("round-trip mismatch")
	}

	lower := bytes.ToLower([]byte(encoded))
	decoded, err = DecodeRecoveryKey(string(lower))
	if err != nil {
		t.Fatalf("lowercase decode: %v", err)
	}
	if !bytes.Equal(decoded, key) {
		t.Fatal("lowercase round-trip mismatch")
	}

	ambiguous := bytes.ReplaceAll([]byte(encoded), []byte("1"), []byte("I"))
	ambiguous = bytes.ReplaceAll(ambiguous, []byte("0"), []byte("O"))
	if _, err := DecodeRecoveryKey(string(ambiguous)); err != nil {
		t.Fatalf("ambiguous character normalization failed: %v", err)
	}

	bad := []byte(encoded)
	if bad[0] == '0' {
		bad[0] = '1'
	} else {
		bad[0] = '0'
	}
	if _, err := DecodeRecoveryKey(string(bad)); err == nil {
		t.Fatal("typo accepted")
	}
	if _, err := DecodeRecoveryKey("too-short"); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestRewrapPasswordKeepsVaultRoot(t *testing.T) {
	v, material, privateKey, userID := newTestVault(t)
	if err := v.RewrapPassword(userID, material.VK, "new password"); err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if _, err := v.UnlockWithPassword(userID, "correct horse battery staple"); err == nil {
		t.Fatal("old password still accepted")
	}
	vk, err := v.UnlockWithPassword(userID, "new password")
	if err != nil {
		t.Fatalf("new password: %v", err)
	}
	if !bytes.Equal(vk, material.VK) {
		t.Fatal("rewrap changed the VK")
	}
	recovered, err := v.PrivateKey(userID, vk)
	if err != nil || !bytes.Equal(recovered, privateKey) {
		t.Fatalf("private key changed: %v", err)
	}
	if _, err := v.UnlockWithRecoveryKey(userID, EncodeRecoveryKey(material.RecoveryKey)); err != nil {
		t.Fatalf("recovery envelope did not survive rewrap: %v", err)
	}
}

func TestOldClientPasswordChangeHealsThroughBridge(t *testing.T) {
	v, material, privateKey, userID := newTestVault(t)

	// An old client re-encrypts the same private key with a new password.
	encrypted, salt, err := crypto.EncryptPrivateKey(privateKey, "old-client-new-password")
	if err != nil {
		t.Fatalf("legacy encrypt: %v", err)
	}
	recoveredPrivateKey, err := crypto.DecryptPrivateKey(encrypted, "old-client-new-password", salt)
	if err != nil {
		t.Fatalf("legacy decrypt: %v", err)
	}

	vk, err := v.UnlockWithBridge(userID, recoveredPrivateKey)
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	if !bytes.Equal(vk, material.VK) {
		t.Fatal("bridge returned a different VK")
	}

	if err := v.RewrapPassword(userID, vk, "old-client-new-password"); err != nil {
		t.Fatalf("rewrap after bridge: %v", err)
	}
	if _, err := v.UnlockWithPassword(userID, "old-client-new-password"); err != nil {
		t.Fatalf("healed password envelope: %v", err)
	}
	if _, err := v.UnlockWithRecoveryKey(userID, EncodeRecoveryKey(material.RecoveryKey)); err != nil {
		t.Fatalf("recovery envelope after bridge: %v", err)
	}
}

func TestBridgeMissingRejected(t *testing.T) {
	v, _, privateKey, userID := newTestVault(t)
	v.Bridge = nil
	if _, err := v.UnlockWithBridge(userID, privateKey); err == nil {
		t.Fatal("missing bridge accepted")
	}
	if _, err := v.PrivateKey(userID, bytes.Repeat([]byte{0x99}, KeySize)); err == nil {
		t.Fatal("wrong VK opened the private key")
	}
}

func TestMultiDeviceRoundTrip(t *testing.T) {
	v, material, privateKey, userID := newTestVault(t)
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var second Vault
	if err := json.Unmarshal(encoded, &second); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	vk, err := second.UnlockWithPassword(userID, "correct horse battery staple")
	if err != nil {
		t.Fatalf("second device unlock: %v", err)
	}
	if !bytes.Equal(vk, material.VK) {
		t.Fatal("second device got a different VK")
	}
	got, err := second.PrivateKey(userID, vk)
	if err != nil || !bytes.Equal(got, privateKey) {
		t.Fatalf("second device private key mismatch: %v", err)
	}
	if err := second.Validate(); err != nil {
		t.Fatalf("round-tripped record invalid: %v", err)
	}
}

func TestCreateUsesFreshRandomness(t *testing.T) {
	privateKey, _, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	a, aMaterial, err := Create("user-1", "password", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	b, bMaterial, err := Create("user-1", "password", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(aMaterial.VK, bMaterial.VK) {
		t.Fatal("two vaults reused the same VK")
	}
	if bytes.Equal(aMaterial.RecoveryKey, bMaterial.RecoveryKey) {
		t.Fatal("two vaults reused the same recovery key")
	}
	if a.SealedPrivateKey.Ciphertext == b.SealedPrivateKey.Ciphertext {
		t.Fatal("two vaults reused the same private-key ciphertext")
	}
}

func TestAADIsLengthPrefixed(t *testing.T) {
	a := envelopeAAD("ab", "c", TypePassword, "", AADVersion)
	b := envelopeAAD("a", "bc", TypePassword, "", AADVersion)
	if bytes.Equal(a, b) {
		t.Fatal("field boundary collision")
	}
	if bytes.Equal(envelopeAAD("u", "e", TypePassword, "", AADVersion), envelopeAAD("u", "e", TypeRecovery, "", AADVersion)) {
		t.Fatal("type is not domain-separated")
	}
}
