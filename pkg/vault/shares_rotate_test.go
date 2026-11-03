package vault

import (
	"bytes"
	"testing"
)

// TestRotateShares regenerates both shares under a new password and a new
// OPAQUE export key, and the resulting vault still unlocks to the same VK with
// the new credentials while the old export key no longer works.
func TestRotateShares(t *testing.T) {
	const (
		userID   = "rotate-user"
		password = "original-password"
	)
	privateKey := bytes.Repeat([]byte{0x11}, KeySize)
	exportKey := bytes.Repeat([]byte{0x22}, KeySize)

	v, material, err := CreateSplit(userID, password, exportKey, privateKey)
	if err != nil {
		t.Fatalf("CreateSplit: %v", err)
	}
	if !v.IsSplit() {
		t.Fatal("CreateSplit did not produce a split vault")
	}

	vk, err := v.UnlockWithShares(userID, password, exportKey)
	if err != nil {
		t.Fatalf("UnlockWithShares: %v", err)
	}
	if !bytes.Equal(vk, material.VK) {
		t.Fatal("unlocked VK does not match the material")
	}
	if _, err := v.PrivateKey(userID, vk); err != nil {
		t.Fatalf("PrivateKey: %v", err)
	}

	// Rotate to a new password and a new export key (the OPAQUE record rotated).
	newPassword := "rotated-password"
	newExportKey := bytes.Repeat([]byte{0x33}, KeySize)
	if err := v.RotateShares(userID, vk, newPassword, newExportKey); err != nil {
		t.Fatalf("RotateShares: %v", err)
	}
	if err := v.Validate(); err != nil {
		t.Fatalf("rotated vault fails validation: %v", err)
	}

	// Old export key must no longer open the share; the new one must.
	if _, err := v.UnlockWithShares(userID, newPassword, exportKey); err == nil {
		t.Error("rotated vault opened with the OLD export key")
	}
	vk2, err := v.UnlockWithShares(userID, newPassword, newExportKey)
	if err != nil {
		t.Fatalf("UnlockWithShares after rotation: %v", err)
	}
	if !bytes.Equal(vk2, vk) {
		t.Error("rotated vault unlocked to a different VK")
	}
	if _, err := v.PrivateKey(userID, vk2); err != nil {
		t.Fatalf("PrivateKey after rotation: %v", err)
	}
}

// TestRotateSharesRejectsV1 confirms the helper refuses a non-split vault.
func TestRotateSharesRejectsV1(t *testing.T) {
	const userID = "rotate-v1"
	privateKey := bytes.Repeat([]byte{0x44}, KeySize)
	v, _, err := Create(userID, "pw", privateKey)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	exportKey := bytes.Repeat([]byte{0x55}, KeySize)
	err = v.RotateShares(userID, bytes.Repeat([]byte{0x66}, KeySize), "newpw", exportKey)
	if err == nil {
		t.Fatal("RotateShares accepted a v1 vault")
	}
}
