package vault

import (
	"bytes"
	"testing"
)

func splitFixture(t *testing.T) (v *Vault, vk, privateKey, exportKey []byte, password string) {
	t.Helper()
	password = "correct horse battery staple"
	exportKey = bytes.Repeat([]byte{0x42}, KeySize)
	privateKey = bytes.Repeat([]byte{0x07}, KeySize)
	v, material, err := CreateSplit("user-1", password, exportKey, privateKey)
	if err != nil {
		t.Fatalf("create split vault: %v", err)
	}
	return v, material.VK, privateKey, exportKey, password
}

func TestSplitVaultRoundTrip(t *testing.T) {
	v, vk, privateKey, exportKey, password := splitFixture(t)

	got, err := v.UnlockWithShares("user-1", password, exportKey)
	if err != nil {
		t.Fatalf("unlock with shares: %v", err)
	}
	if !bytes.Equal(got, vk) {
		t.Fatal("unlock returned the wrong vault key")
	}
	pk, err := v.PrivateKey("user-1", got)
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	if !bytes.Equal(pk, privateKey) {
		t.Fatal("private key mismatch after split unlock")
	}
	if err := v.Validate(); err != nil {
		t.Fatalf("split vault failed validation: %v", err)
	}
}

// TestPasswordShareAloneIsUseless simulates the breach Hani described: the
// attacker holds a copy of the server data (the vault JSON) and has cracked
// the password offline. They recover the password share, but without the
// OPAQUE share the vault key stays out of reach.
func TestPasswordShareAloneIsUseless(t *testing.T) {
	v, vk, _, _, password := splitFixture(t)

	share, err := v.openPasswordShare("user-1", password)
	if err != nil {
		t.Fatalf("open password share: %v", err)
	}
	if bytes.Equal(share, vk) {
		t.Fatal("password share equals the vault key; the split is broken")
	}
	if _, err := v.PrivateKey("user-1", share); err == nil {
		t.Fatal("password share alone decrypted the private key")
	}
}

// TestOpaqueShareAloneIsUseless covers the mirror image: an attacker who
// somehow obtained the export key but not the password gets nothing.
func TestOpaqueShareAloneIsUseless(t *testing.T) {
	v, vk, _, exportKey, _ := splitFixture(t)

	share, err := v.openOpaqueShare("user-1", exportKey)
	if err != nil {
		t.Fatalf("open opaque share: %v", err)
	}
	if bytes.Equal(share, vk) {
		t.Fatal("opaque share equals the vault key; the split is broken")
	}
	if _, err := v.PrivateKey("user-1", share); err == nil {
		t.Fatal("opaque share alone decrypted the private key")
	}
}

func TestSplitRejectsWrongPassword(t *testing.T) {
	v, _, _, exportKey, _ := splitFixture(t)
	if _, err := v.UnlockWithShares("user-1", "wrong password", exportKey); err == nil {
		t.Fatal("unlock succeeded with the wrong password")
	}
}

func TestSplitRejectsWrongExportKey(t *testing.T) {
	v, _, _, _, password := splitFixture(t)
	wrong := bytes.Repeat([]byte{0x99}, KeySize)
	if _, err := v.UnlockWithShares("user-1", password, wrong); err == nil {
		t.Fatal("unlock succeeded with the wrong export key")
	}
}

// TestV1UnlockRefusedOnSplitVault pins the fail-closed behaviour: a caller
// that treats a v2 password envelope as a v1 envelope must get a loud
// error, never a share it mistakes for the VK.
func TestV1UnlockRefusedOnSplitVault(t *testing.T) {
	v, _, _, _, password := splitFixture(t)
	if _, err := v.UnlockWithPassword("user-1", password); err == nil {
		t.Fatal("v1 password unlock succeeded on a split-share vault")
	}
}

// TestMigrateV1ToV2PreservesVaultKey proves the migration path: an existing
// v1 vault keeps its VK (so the sealed private key, bridge, recovery
// envelopes, and proof key all stay valid) while gaining the split.
func TestMigrateV1ToV2PreservesVaultKey(t *testing.T) {
	password := "migration password"
	privateKey := bytes.Repeat([]byte{0x11}, KeySize)
	v1, material, err := Create("user-1", password, privateKey)
	if err != nil {
		t.Fatalf("create v1 vault: %v", err)
	}

	exportKey := bytes.Repeat([]byte{0x42}, KeySize)
	if err := v1.MigrateToShares("user-1", password, material.VK, exportKey); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := v1.Validate(); err != nil {
		t.Fatalf("migrated vault failed validation: %v", err)
	}

	got, err := v1.UnlockWithShares("user-1", password, exportKey)
	if err != nil {
		t.Fatalf("unlock migrated vault: %v", err)
	}
	if !bytes.Equal(got, material.VK) {
		t.Fatal("migration changed the vault key")
	}

	// The old v1 unlock path must now refuse, so nothing downstream can
	// mistake the share for the VK.
	if _, err := v1.UnlockWithPassword("user-1", password); err == nil {
		t.Fatal("v1 unlock still works after migration")
	}
}

// TestSplitVaultNeedsBothEnvelopes pins the structural validation rule.
func TestSplitVaultNeedsBothEnvelopes(t *testing.T) {
	v, _, _, _, _ := splitFixture(t)
	for i, env := range v.Envelopes {
		if env.Type == TypeOpaque {
			v.Envelopes = append(v.Envelopes[:i], v.Envelopes[i+1:]...)
			break
		}
	}
	if err := v.Validate(); err == nil {
		t.Fatal("split vault without an opaque envelope passed validation")
	}
}

// TestRewrapOpaqueKeepsShare covers the rotation path: re-registering the
// OPAQUE record (password change, recovery re-enrollment) rotates the
// export key, and the share must unwrap identically under the new key.
func TestRewrapOpaqueKeepsShare(t *testing.T) {
	v, vk, _, exportKey, password := splitFixture(t)

	newExportKey := bytes.Repeat([]byte{0x24}, KeySize)
	share, err := v.openOpaqueShare("user-1", exportKey)
	if err != nil {
		t.Fatalf("open opaque share: %v", err)
	}
	if err := v.RewrapOpaque("user-1", share, newExportKey); err != nil {
		t.Fatalf("rewrap opaque: %v", err)
	}
	if _, err := v.UnlockWithShares("user-1", password, exportKey); err == nil {
		t.Fatal("old export key still works after rewrap")
	}
	got, err := v.UnlockWithShares("user-1", password, newExportKey)
	if err != nil {
		t.Fatalf("unlock after rewrap: %v", err)
	}
	if !bytes.Equal(got, vk) {
		t.Fatal("rewrap changed the vault key")
	}
}

// TestV1VaultUnaffected guards the existing scheme: v1 vaults keep their
// exact v1 semantics.
func TestV1VaultUnaffected(t *testing.T) {
	password := "v1 password"
	privateKey := bytes.Repeat([]byte{0x33}, KeySize)
	v, _, err := Create("user-1", password, privateKey)
	if err != nil {
		t.Fatalf("create v1: %v", err)
	}
	vk, err := v.UnlockWithPassword("user-1", password)
	if err != nil {
		t.Fatalf("v1 unlock: %v", err)
	}
	if _, err := v.UnlockWithShares("user-1", password, bytes.Repeat([]byte{0x42}, KeySize)); err == nil {
		t.Fatal("share unlock succeeded on a v1 vault")
	}
	pk, err := v.PrivateKey("user-1", vk)
	if err != nil || !bytes.Equal(pk, privateKey) {
		t.Fatal("v1 private key round trip broken")
	}
}
