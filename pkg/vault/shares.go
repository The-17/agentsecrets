package vault

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

// shares.go implements the v2 split-share vault scheme.
//
// A v2 vault splits the Vault Key into two random 32-byte shares:
//
//	VK = K1 ⊕ K2
//
// K1 is wrapped by the password envelope (Argon2id), exactly as the v1
// envelope wrapped the VK itself. K2 is wrapped by an "opaque" envelope
// whose KEK is derived from the OPAQUE export key — a 256-bit secret that
// exists only on the client after a live OPAQUE login exchange and is
// never stored by client or server.
//
// Security properties, measured against the v1 scheme:
//
//   - Database copy + password guesses (the breach case): the attacker can
//     crack the password envelope offline at Argon2id cost and recover K1,
//     but K2 requires the export key, which is computable only with the
//     sidecar's OPRF seed — deployment key material, not database content.
//     The vault is not offline-attackable from a database dump.
//   - Database + sidecar key material: an offline dictionary attack at one
//     Argon2id evaluation per guess — identical resistance to the v1
//     password envelope. Never worse than v1.
//   - Malicious server at login time: the OPRF holder can derive the
//     export key (K2), but the password never leaves the client, so K1
//     stays out of reach and the vault stays sealed — same as v1.
//   - Recovery is unchanged: the recovery envelope wraps the full VK
//     under the 256-bit recovery key.
//
// The unlock UX is identical to v1: the user types their password, the
// OPAQUE exchange produces the export key, and both shares come back
// together. No new secret is introduced for the user to safeguard.

const (
	// TypeOpaque is the v2 OPAQUE-share envelope type.
	TypeOpaque = "opaque"

	// Version2 is the vault record format carrying split shares. Old
	// clients reject it via ErrVersion, which fails closed: a v1 client
	// must never mistake a password-share envelope for a full-VK envelope.
	Version2 = 2

	// opaqueShareInfo is the HKDF info string for the OPAQUE-share KEK.
	opaqueShareInfo = "as:v1/opaque-share"

	// MinClientVersionV2 is the first client release that understands the v2
	// split-share vault. A v2 vault names it so an older CLI fails with a
	// clear upgrade message instead of a parse error.
	MinClientVersionV2 = "4.1.0"
)

// xorBytes returns a ⊕ b. Both slices must be the same length.
func xorBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("vault: share length mismatch")
	}
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out, nil
}

// makeOpaqueEnvelope wraps a share under a KEK derived from the OPAQUE
// export key.
func makeOpaqueEnvelope(userID string, exportKey, share []byte) (Envelope, error) {
	if len(exportKey) != KeySize {
		return Envelope{}, fmt.Errorf("vault: opaque export key must be %d bytes", KeySize)
	}
	salt, err := randomBytes(SaltSize)
	if err != nil {
		return Envelope{}, err
	}
	kek, err := hkdfKey(exportKey, salt, opaqueShareInfo)
	if err != nil {
		return Envelope{}, err
	}
	env, err := newEnvelope(TypeOpaque, KDFHKDF, kek, share, userID, "", nil)
	if err != nil {
		return Envelope{}, err
	}
	env.Salt = b64(salt)
	return env, nil
}

// makePasswordShareEnvelope wraps a share under the password KEK. It is the
// v1 password envelope applied to a 32-byte share instead of the VK.
func makePasswordShareEnvelope(userID, password string, share []byte) (Envelope, error) {
	return makePasswordEnvelope(userID, password, share)
}

// CreateSplit builds a v2 vault whose VK is split into a password share and
// an OPAQUE share. The returned Material matches Create: the recovery key is
// shown once and never stored.
func CreateSplit(userID, password string, exportKey, privateKey []byte) (*Vault, *Material, error) {
	if userID == "" {
		return nil, nil, fmt.Errorf("vault: user id is required")
	}
	if len(privateKey) != KeySize {
		return nil, nil, fmt.Errorf("vault: private key must be %d bytes", KeySize)
	}

	vk, err := randomBytes(KeySize)
	if err != nil {
		return nil, nil, err
	}
	recoveryKey, err := randomBytes(KeySize)
	if err != nil {
		return nil, nil, err
	}
	k1, err := randomBytes(KeySize)
	if err != nil {
		return nil, nil, err
	}
	k2, err := xorBytes(vk, k1)
	if err != nil {
		return nil, nil, err
	}

	privateNonce, privateCT, err := sealRaw(vk, privateKey, privateKeyAAD(userID, AADVersion))
	if err != nil {
		return nil, nil, err
	}
	bridge, err := makeBridge(userID, privateKey, vk)
	if err != nil {
		return nil, nil, err
	}
	passwordEnv, err := makePasswordShareEnvelope(userID, password, k1)
	if err != nil {
		return nil, nil, err
	}
	opaqueEnv, err := makeOpaqueEnvelope(userID, exportKey, k2)
	if err != nil {
		return nil, nil, err
	}
	recoveryEnv, err := makeRecoveryEnvelope(userID, recoveryKey, vk)
	if err != nil {
		return nil, nil, err
	}

	v := &Vault{
		Version:      Version2,
		VaultVersion: 1,
		SealedPrivateKey: Sealed{
			Nonce:      b64(privateNonce),
			Ciphertext: b64(privateCT),
			AADVersion: AADVersion,
		},
		Bridge:    bridge,
		Envelopes: []Envelope{passwordEnv, opaqueEnv, recoveryEnv},
	}
	if err := v.Sign(userID, vk); err != nil {
		return nil, nil, err
	}
	return v, &Material{VK: vk, RecoveryKey: recoveryKey}, nil
}

// openPasswordShare unwraps the password share. v2 only.
func (v *Vault) openPasswordShare(userID, password string) ([]byte, error) {
	env := v.findEnvelope(TypePassword)
	if env == nil {
		return nil, ErrEnvelopeNotFound
	}
	salt, err := unb64(env.Salt)
	if err != nil {
		return nil, err
	}
	params, err := env.kdfParams()
	if err != nil {
		return nil, err
	}
	kek := argon2.IDKey([]byte(password), salt, params.T, params.M, params.P, KeySize)
	return v.openEnvelope(env, userID, kek)
}

// openOpaqueShare unwraps the OPAQUE share with the export key. v2 only.
func (v *Vault) openOpaqueShare(userID string, exportKey []byte) ([]byte, error) {
	env := v.findEnvelope(TypeOpaque)
	if env == nil {
		return nil, ErrEnvelopeNotFound
	}
	salt, err := unb64(env.Salt)
	if err != nil {
		return nil, err
	}
	kek, err := hkdfKey(exportKey, salt, opaqueShareInfo)
	if err != nil {
		return nil, err
	}
	return v.openEnvelope(env, userID, kek)
}

// UnlockWithShares recovers the VK from both shares. The password is typed
// by the user; the export key comes from the OPAQUE login exchange that
// already authenticated this session.
func (v *Vault) UnlockWithShares(userID, password string, exportKey []byte) ([]byte, error) {
	if v.Version != Version2 {
		return nil, fmt.Errorf("%w: not a split-share vault", ErrVersion)
	}
	k1, err := v.openPasswordShare(userID, password)
	if err != nil {
		return nil, err
	}
	k2, err := v.openOpaqueShare(userID, exportKey)
	if err != nil {
		return nil, err
	}
	return xorBytes(k1, k2)
}

// MigrateToShares converts an unlocked v1 vault to the v2 split-share
// scheme. The VK is preserved, so the sealed private key, the bridge, the
// recovery envelopes, and the proof key are all untouched; only the
// password envelope's payload changes (it now wraps a share) and the
// OPAQUE-share envelope is added. The caller bumps the version, signs, and
// uploads.
func (v *Vault) MigrateToShares(userID, password string, vk, exportKey []byte) error {
	if v.Version != Version {
		return fmt.Errorf("%w: migrate expects a v1 vault", ErrVersion)
	}
	if len(vk) != KeySize {
		return fmt.Errorf("vault: vk must be %d bytes", KeySize)
	}
	env := v.findEnvelope(TypePassword)
	if env == nil {
		return ErrEnvelopeNotFound
	}

	k1, err := randomBytes(KeySize)
	if err != nil {
		return err
	}
	k2, err := xorBytes(vk, k1)
	if err != nil {
		return err
	}

	// Rewrap the existing password envelope around the share, reusing the
	// v1 rewrap path (fresh salt, current KDF parameters).
	if err := v.RewrapPassword(userID, k1, password); err != nil {
		return err
	}
	opaqueEnv, err := makeOpaqueEnvelope(userID, exportKey, k2)
	if err != nil {
		return err
	}
	v.Envelopes = append(v.Envelopes, opaqueEnv)
	v.Version = Version2
	return nil
}

// RewrapOpaque re-wraps the OPAQUE share under a new export key. The OPAQUE
// record rotates on every re-registration (password change, recovery
// re-enrollment), which rotates the export key, so the share must be
// re-wrapped whenever that happens. The share itself does not change.
func (v *Vault) RewrapOpaque(userID string, share, newExportKey []byte) error {
	env := v.findEnvelope(TypeOpaque)
	if env == nil {
		return ErrEnvelopeNotFound
	}
	salt, err := randomBytes(SaltSize)
	if err != nil {
		return err
	}
	kek, err := hkdfKey(newExportKey, salt, opaqueShareInfo)
	if err != nil {
		return err
	}
	nonce, ct, err := sealRaw(kek, share, envelopeAAD(userID, env.ID, env.Type, env.CredentialID, env.AADVersion))
	if err != nil {
		return err
	}
	env.Salt = b64(salt)
	env.Nonce = b64(nonce)
	env.Ciphertext = b64(ct)
	return nil
}

// IsSplit reports whether this vault uses the v2 split-share scheme.
func (v *Vault) IsSplit() bool { return v.Version == Version2 }
