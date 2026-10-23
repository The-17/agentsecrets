package vault

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestProofSignsAndVerifies(t *testing.T) {
	v, _, _, userID := newTestVault(t)
	if err := v.Verify(userID); err != nil {
		t.Fatalf("verify fresh vault: %v", err)
	}
	pinned := v.VaultPubKey
	if err := v.PinPublicKey(pinned); err != nil {
		t.Fatalf("pin matching key: %v", err)
	}
	if err := v.PinPublicKey("other"); err == nil {
		t.Fatal("pin accepted a different key")
	}

	v.VaultVersion++
	if err := v.Verify(userID); err == nil {
		t.Fatal("proof accepted after version change")
	}
}

func TestProofRejectsTamperedEnvelope(t *testing.T) {
	v, _, _, userID := newTestVault(t)
	raw, err := base64.StdEncoding.DecodeString(v.Envelopes[0].Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 1
	v.Envelopes[0].Ciphertext = base64.StdEncoding.EncodeToString(raw)
	if err := v.Verify(userID); err == nil {
		t.Fatal("proof accepted a tampered envelope")
	}
}

func TestProofBindsUserID(t *testing.T) {
	v, _, _, userID := newTestVault(t)
	if err := v.Verify("user-2"); err == nil {
		t.Fatal("proof accepted a different user id")
	}
	if err := v.Verify(userID); err != nil {
		t.Fatalf("proof failed for the right user: %v", err)
	}
}

func TestSignatureChangesWithVK(t *testing.T) {
	v, _, _, userID := newTestVault(t)
	original := v.Proof.Signature
	if err := v.Sign(userID, bytes.Repeat([]byte{0x77}, KeySize)); err != nil {
		t.Fatalf("re-sign: %v", err)
	}
	if v.Proof.Signature == original {
		t.Fatal("signature did not change with the signing key")
	}
}

func TestKDFPolicyFloor(t *testing.T) {
	v, _, _, userID := newTestVault(t)
	env := v.findEnvelope(TypePassword)
	if env == nil {
		t.Fatal("missing password envelope")
	}
	env.Params = &KDFParams{M: MinArgonMemory - 1, T: MinArgonTime, P: MinArgonThreads}
	if _, err := v.UnlockWithPassword(userID, "correct horse battery staple"); err == nil {
		t.Fatal("weak KDF accepted")
	}
	env.Params = &KDFParams{M: MaxArgonMemory + 1, T: MinArgonTime, P: MinArgonThreads}
	if _, err := v.UnlockWithPassword(userID, "correct horse battery staple"); err == nil {
		t.Fatal("oversized KDF accepted")
	}
}

func TestRemoveEnvelopePolicy(t *testing.T) {
	v, _, _, _ := newTestVault(t)
	passwordID := v.findEnvelope(TypePassword).ID

	if err := v.RemoveEnvelope(passwordID); err == nil {
		t.Fatal("removed password before recovery was confirmed")
	}

	confirmed, _, _, _ := newTestVault(t)
	confirmed.ConfirmRecovery()
	if err := confirmed.RemoveEnvelope(confirmed.findEnvelope(TypeRecovery).ID); err == nil {
		t.Fatal("removed the last recovery factor")
	}
	if err := confirmed.RemoveEnvelope(confirmed.findEnvelope(TypePassword).ID); err != nil {
		t.Fatalf("remove password with recovery present: %v", err)
	}

	withPasskey, material, _, userID := newTestVault(t)
	withPasskey.ConfirmRecovery()
	if _, err := withPasskey.AddPasskeyEnvelope(userID, material.VK, bytes.Repeat([]byte{0x55}, KeySize), "cred-1"); err != nil {
		t.Fatal(err)
	}
	if err := withPasskey.RemoveEnvelope(withPasskey.findEnvelope(TypeRecovery).ID); err != nil {
		t.Fatalf("remove recovery with passkey present: %v", err)
	}
}

func TestRemoveEnvelopeRejectsUnknownAndOnly(t *testing.T) {
	v, _, _, _ := newTestVault(t)
	if err := v.RemoveEnvelope("missing"); err == nil {
		t.Fatal("removed an unknown envelope")
	}
	v.Envelopes = v.Envelopes[:1]
	if err := v.RemoveEnvelope(v.Envelopes[0].ID); err == nil {
		t.Fatal("removed the only envelope")
	}
}

func TestRotateRecoveryKey(t *testing.T) {
	v, material, _, userID := newTestVault(t)
	oldKey := EncodeRecoveryKey(material.RecoveryKey)

	newKey, newID, err := v.RotateRecoveryKey(userID, material.VK)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if newKey == oldKey {
		t.Fatal("rotation reused the old key")
	}
	if _, err := v.UnlockWithRecoveryKey(userID, oldKey); err != nil {
		t.Fatalf("old key stopped working before retirement: %v", err)
	}
	if _, err := v.UnlockWithRecoveryKey(userID, newKey); err != nil {
		t.Fatalf("new key does not work: %v", err)
	}

	removed, err := v.RemoveRecoveryEnvelopesExcept(newID)
	if err != nil {
		t.Fatalf("retire old envelopes: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed %d envelopes, want 1", removed)
	}
	if _, err := v.UnlockWithRecoveryKey(userID, oldKey); err == nil {
		t.Fatal("retired key still works")
	}
	if _, err := v.UnlockWithRecoveryKey(userID, newKey); err != nil {
		t.Fatalf("new key failed after retirement: %v", err)
	}
}

func TestRemoveRecoveryEnvelopesExceptRequiresRecoveryID(t *testing.T) {
	v, _, _, _ := newTestVault(t)
	if _, err := v.RemoveRecoveryEnvelopesExcept(v.findEnvelope(TypePassword).ID); err == nil {
		t.Fatal("accepted a non-recovery keep id")
	}
}

func TestValidateStructure(t *testing.T) {
	base, _, _, _ := newTestVault(t)
	cases := []struct {
		name   string
		mutate func(*Vault)
	}{
		{"format version", func(v *Vault) { v.Version = 2 }},
		{"zero version", func(v *Vault) { v.VaultVersion = 0 }},
		{"missing pubkey", func(v *Vault) { v.VaultPubKey = "" }},
		{"no envelopes", func(v *Vault) { v.Envelopes = nil }},
		{"duplicate id", func(v *Vault) { v.Envelopes[1].ID = v.Envelopes[0].ID }},
		{"bad kdf", func(v *Vault) { v.Envelopes[0].KDF = "pbkdf2" }},
		{"bad aad", func(v *Vault) { v.Envelopes[0].AADVersion = 9 }},
		{"empty salt", func(v *Vault) { v.Envelopes[0].Salt = "" }},
		{"confirmed without factor", func(v *Vault) {
			v.RecoveryConfirmed = true
			v.Envelopes = []Envelope{*v.findEnvelope(TypePassword)}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := cloneVault(base)
			tc.mutate(v)
			if err := v.Validate(); err == nil {
				t.Fatalf("invalid record accepted: %s", tc.name)
			}
		})
	}
	if err := cloneVault(base).Validate(); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
}

// TestUnknownEnvelopeTypeIsTolerated is the forward-compatibility contract.
//
// A vault is shared state written by whichever client enrolled a factor, and
// installed clients cannot be updated. If an unknown envelope type were fatal,
// a newer client adding a factor would make the whole vault unreadable on every
// older client. Older clients must ignore what they cannot unlock.
func TestUnknownEnvelopeTypeIsTolerated(t *testing.T) {
	base, _, _, userID := newTestVault(t)
	v := cloneVault(base)
	// Mutate an envelope that is not the password one, so the password factor
	// remains available to prove the vault still unlocks.
	for i := range v.Envelopes {
		if v.Envelopes[i].Type == TypeRecovery {
			v.Envelopes[i].Type = "sms"
			break
		}
	}

	if err := v.Validate(); err != nil {
		t.Fatalf("unknown envelope type made the vault unreadable: %v", err)
	}

	// The known envelope must still work: tolerance must not mean the vault
	// stops unlocking through a factor this build does understand.
	if _, err := v.UnlockWithPassword(userID, "correct horse battery staple"); err != nil {
		t.Fatalf("password unlock broke after an unknown envelope was added: %v", err)
	}
}

func cloneVault(v *Vault) *Vault {
	out := *v
	out.Envelopes = append([]Envelope(nil), v.Envelopes...)
	if v.Bridge != nil {
		bridge := *v.Bridge
		out.Bridge = &bridge
	}
	if v.Proof != nil {
		proof := *v.Proof
		out.Proof = &proof
	}
	return &out
}
