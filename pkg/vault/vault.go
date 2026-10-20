// Package vault implements the v4 vault-unlock layer.
//
// The vault root is a random 32-byte Vault Key (VK). The X25519 private key is
// sealed under the VK, and the VK is wrapped by independent envelopes:
// password (Argon2id), recovery key (HKDF), and passkey (WebAuthn PRF). A
// private-key bridge wraps the VK under the X25519 private key so a password
// change made by an old client can be healed by a new client.
//
// The server stores ciphertext and metadata only. It never receives the VK, the
// recovery key, the private key, or a decrypted secret.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	// Version is the vault record format version.
	Version = 1
	// AADVersion is the associated-data layout version.
	AADVersion = 1

	KeySize   = 32
	SaltSize  = 32
	NonceSize = 12

	// DefaultArgonMemory is 64 MiB, expressed in KiB as Argon2 expects.
	DefaultArgonMemory  = 64 * 1024
	DefaultArgonTime    = 3
	DefaultArgonThreads = 4

	MinArgonMemory  = 64 * 1024
	MinArgonTime    = 3
	MinArgonThreads = 4
	MaxArgonMemory  = 1024 * 1024
)

const (
	TypePassword = "password"
	TypeRecovery = "recovery"
	TypePasskey  = "passkey"

	KDFArgon2 = "argon2id"
	KDFHKDF   = "hkdf-sha256"
)

var (
	ErrEnvelopeNotFound = errors.New("vault: envelope not found")
	ErrWeakKDF          = errors.New("vault: KDF parameters below policy floor")
	ErrRecoveryKey      = errors.New("vault: recovery key did not unlock any envelope")
	ErrProof            = errors.New("vault: invalid vault proof")
	ErrVersion          = errors.New("vault: unsupported vault format")
	ErrPolicy           = errors.New("vault: envelope removal refused by policy")
)

// KDFParams are the Argon2id parameters stored with a password envelope.
type KDFParams struct {
	M uint32 `json:"m"`
	T uint32 `json:"t"`
	P uint8  `json:"p"`
}

// DefaultKDFParams returns the current password KDF parameters.
func DefaultKDFParams() KDFParams {
	return KDFParams{M: DefaultArgonMemory, T: DefaultArgonTime, P: DefaultArgonThreads}
}

// Envelope wraps the VK under one unlock factor.
type Envelope struct {
	ID           string     `json:"id"`
	Type         string     `json:"type"`
	KDF          string     `json:"kdf"`
	Params       *KDFParams `json:"params,omitempty"`
	CredentialID string     `json:"credential_id,omitempty"`
	Salt         string     `json:"salt"`
	Nonce        string     `json:"nonce"`
	Ciphertext   string     `json:"ciphertext"`
	AADVersion   int        `json:"aad_version"`
	CreatedAt    string     `json:"created_at,omitempty"`
}

// Sealed is an AES-256-GCM ciphertext with its nonce.
type Sealed struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	AADVersion int    `json:"aad_version"`
}

// Bridge wraps the VK under a key derived from the X25519 private key.
type Bridge struct {
	KDF        string `json:"kdf"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	AADVersion int    `json:"aad_version"`
}

// Proof is the Ed25519 signature over the vault envelope set.
type Proof struct {
	Signature string `json:"signature"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
}

// Vault is the client-held unlock record stored by the server.
type Vault struct {
	Version           int        `json:"version"`
	VaultVersion      int        `json:"vault_version"`
	VaultPubKey       string     `json:"vault_pubkey"`
	SealedPrivateKey  Sealed     `json:"private_key"`
	Bridge            *Bridge    `json:"bridge,omitempty"`
	Envelopes         []Envelope `json:"envelopes"`
	RecoveryConfirmed bool       `json:"recovery_confirmed"`
	MinClientVersion  string     `json:"min_client_version,omitempty"`
	Proof             *Proof     `json:"proof,omitempty"`
}

// Material is returned once at vault creation. The recovery key must be shown
// to the user and never stored by the client.
type Material struct {
	VK          []byte
	RecoveryKey []byte
}

func randomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("vault: random: %w", err)
	}
	return b, nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("vault: decode base64: %w", err)
	}
	return b, nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hkdfKey(secret, salt []byte, info string) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, salt, []byte(info))
	out := make([]byte, KeySize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("vault: hkdf: %w", err)
	}
	return out, nil
}

func appendField(dst, field []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(field)))
	return append(append(dst, l[:]...), field...)
}

func envelopeAAD(userID, envelopeID, typ, credentialID string, version int) []byte {
	var b []byte
	b = appendField(b, []byte("as-vault-envelope"))
	b = appendField(b, []byte(userID))
	b = appendField(b, []byte(envelopeID))
	b = appendField(b, []byte(typ))
	b = appendField(b, []byte(credentialID))
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], uint64(version))
	return append(b, v[:]...)
}

func privateKeyAAD(userID string, version int) []byte {
	var b []byte
	b = appendField(b, []byte("as-vault-private-key"))
	b = appendField(b, []byte(userID))
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], uint64(version))
	return append(b, v[:]...)
}

func bridgeAAD(userID string, version int) []byte {
	var b []byte
	b = appendField(b, []byte("as-vault-bridge"))
	b = appendField(b, []byte(userID))
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], uint64(version))
	return append(b, v[:]...)
}

func sealRaw(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("vault: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("vault: gcm: %w", err)
	}
	nonce, err = randomBytes(gcm.NonceSize())
	if err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

func openRaw(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vault: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: gcm: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("vault: bad nonce size")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("vault: open: %w", err)
	}
	return plaintext, nil
}

func (e *Envelope) kdfParams() (KDFParams, error) {
	p := DefaultKDFParams()
	if e.Params != nil {
		p = *e.Params
	}
	if p.M == 0 {
		p.M = DefaultArgonMemory
	}
	if p.T == 0 {
		p.T = DefaultArgonTime
	}
	if p.P == 0 {
		p.P = DefaultArgonThreads
	}
	if p.M < MinArgonMemory || p.T < MinArgonTime || p.P < MinArgonThreads {
		return p, ErrWeakKDF
	}
	if p.M > MaxArgonMemory {
		return p, fmt.Errorf("%w: memory above maximum", ErrWeakKDF)
	}
	return p, nil
}

func newEnvelopeID() (string, error) {
	id, err := randomBytes(8)
	if err != nil {
		return "", err
	}
	return "env_" + hex.EncodeToString(id), nil
}

func newEnvelope(typ, kdf string, kek, vk []byte, userID, credentialID string, params *KDFParams) (Envelope, error) {
	id, err := newEnvelopeID()
	if err != nil {
		return Envelope{}, err
	}
	salt, err := randomBytes(SaltSize)
	if err != nil {
		return Envelope{}, err
	}
	nonce, ct, err := sealRaw(kek, vk, envelopeAAD(userID, id, typ, credentialID, AADVersion))
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		ID:           id,
		Type:         typ,
		KDF:          kdf,
		Params:       params,
		CredentialID: credentialID,
		Salt:         b64(salt),
		Nonce:        b64(nonce),
		Ciphertext:   b64(ct),
		AADVersion:   AADVersion,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func makePasswordEnvelope(userID, password string, vk []byte) (Envelope, error) {
	params := DefaultKDFParams()
	salt, err := randomBytes(SaltSize)
	if err != nil {
		return Envelope{}, err
	}
	kek := argon2.IDKey([]byte(password), salt, params.T, params.M, params.P, KeySize)
	env, err := newEnvelope(TypePassword, KDFArgon2, kek, vk, userID, "", &params)
	if err != nil {
		return Envelope{}, err
	}
	env.Salt = b64(salt)
	return env, nil
}

func makeRecoveryEnvelope(userID string, recoveryKey, vk []byte) (Envelope, error) {
	salt, err := randomBytes(SaltSize)
	if err != nil {
		return Envelope{}, err
	}
	kek, err := hkdfKey(recoveryKey, salt, "as:v1/recovery")
	if err != nil {
		return Envelope{}, err
	}
	env, err := newEnvelope(TypeRecovery, KDFHKDF, kek, vk, userID, "", nil)
	if err != nil {
		return Envelope{}, err
	}
	env.Salt = b64(salt)
	return env, nil
}

func makePasskeyEnvelope(userID string, prf, vk []byte, credentialID string) (Envelope, error) {
	salt, err := randomBytes(SaltSize)
	if err != nil {
		return Envelope{}, err
	}
	kek, err := hkdfKey(prf, salt, "as:v1/passkey/"+credentialID)
	if err != nil {
		return Envelope{}, err
	}
	env, err := newEnvelope(TypePasskey, KDFHKDF, kek, vk, userID, credentialID, nil)
	if err != nil {
		return Envelope{}, err
	}
	env.Salt = b64(salt)
	return env, nil
}

func makeBridge(userID string, privateKey, vk []byte) (*Bridge, error) {
	salt, err := randomBytes(SaltSize)
	if err != nil {
		return nil, err
	}
	kek, err := hkdfKey(privateKey, salt, "as:v1/bridge")
	if err != nil {
		return nil, err
	}
	nonce, ct, err := sealRaw(kek, vk, bridgeAAD(userID, AADVersion))
	if err != nil {
		return nil, err
	}
	return &Bridge{
		KDF:        KDFHKDF,
		Salt:       b64(salt),
		Nonce:      b64(nonce),
		Ciphertext: b64(ct),
		AADVersion: AADVersion,
	}, nil
}

func (v *Vault) findEnvelope(typ string) *Envelope {
	for i := range v.Envelopes {
		if v.Envelopes[i].Type == typ {
			return &v.Envelopes[i]
		}
	}
	return nil
}

func (v *Vault) openEnvelope(env *Envelope, userID string, kek []byte) ([]byte, error) {
	nonce, err := unb64(env.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := unb64(env.Ciphertext)
	if err != nil {
		return nil, err
	}
	aad := envelopeAAD(userID, env.ID, env.Type, env.CredentialID, env.AADVersion)
	return openRaw(kek, nonce, ct, aad)
}

// Create builds a new vault for an existing X25519 keypair.
//
// The returned Material.VK and Material.RecoveryKey are shown or used once and
// are never persisted by the client. The server receives the Vault only.
func Create(userID, password string, privateKey []byte) (*Vault, *Material, error) {
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

	privateNonce, privateCT, err := sealRaw(vk, privateKey, privateKeyAAD(userID, AADVersion))
	if err != nil {
		return nil, nil, err
	}

	bridge, err := makeBridge(userID, privateKey, vk)
	if err != nil {
		return nil, nil, err
	}

	passwordEnv, err := makePasswordEnvelope(userID, password, vk)
	if err != nil {
		return nil, nil, err
	}
	recoveryEnv, err := makeRecoveryEnvelope(userID, recoveryKey, vk)
	if err != nil {
		return nil, nil, err
	}

	v := &Vault{
		Version:      Version,
		VaultVersion: 1,
		SealedPrivateKey: Sealed{
			Nonce:      b64(privateNonce),
			Ciphertext: b64(privateCT),
			AADVersion: AADVersion,
		},
		Bridge:    bridge,
		Envelopes: []Envelope{passwordEnv, recoveryEnv},
	}
	if err := v.Sign(userID, vk); err != nil {
		return nil, nil, err
	}
	return v, &Material{VK: vk, RecoveryKey: recoveryKey}, nil
}

// UnlockWithPassword unwraps the VK with the password envelope.
func (v *Vault) UnlockWithPassword(userID, password string) ([]byte, error) {
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

// UnlockWithRecoveryKey unwraps the VK with any recovery envelope. More than one
// envelope can exist during a rotation, so every candidate is tried.
func (v *Vault) UnlockWithRecoveryKey(userID, encodedKey string) ([]byte, error) {
	key, err := DecodeRecoveryKey(encodedKey)
	if err != nil {
		return nil, err
	}
	for i := range v.Envelopes {
		env := &v.Envelopes[i]
		if env.Type != TypeRecovery {
			continue
		}
		salt, err := unb64(env.Salt)
		if err != nil {
			continue
		}
		kek, err := hkdfKey(key, salt, "as:v1/recovery")
		if err != nil {
			continue
		}
		if vk, err := v.openEnvelope(env, userID, kek); err == nil {
			return vk, nil
		}
	}
	return nil, ErrRecoveryKey
}

// UnlockWithPasskey unwraps the VK with a WebAuthn PRF output.
func (v *Vault) UnlockWithPasskey(userID string, prf []byte, credentialID string) ([]byte, error) {
	for i := range v.Envelopes {
		env := &v.Envelopes[i]
		if env.Type != TypePasskey || env.CredentialID != credentialID {
			continue
		}
		salt, err := unb64(env.Salt)
		if err != nil {
			continue
		}
		kek, err := hkdfKey(prf, salt, "as:v1/passkey/"+credentialID)
		if err != nil {
			continue
		}
		if vk, err := v.openEnvelope(env, userID, kek); err == nil {
			return vk, nil
		}
	}
	return nil, ErrEnvelopeNotFound
}

// UnlockWithBridge unwraps the VK with the X25519 private key. This is only for
// recovering from a password change made by an old client.
func (v *Vault) UnlockWithBridge(userID string, privateKey []byte) ([]byte, error) {
	if v.Bridge == nil {
		return nil, ErrEnvelopeNotFound
	}
	salt, err := unb64(v.Bridge.Salt)
	if err != nil {
		return nil, err
	}
	kek, err := hkdfKey(privateKey, salt, "as:v1/bridge")
	if err != nil {
		return nil, err
	}
	nonce, err := unb64(v.Bridge.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := unb64(v.Bridge.Ciphertext)
	if err != nil {
		return nil, err
	}
	return openRaw(kek, nonce, ct, bridgeAAD(userID, v.Bridge.AADVersion))
}

// PrivateKey decrypts the X25519 private key with the VK.
func (v *Vault) PrivateKey(userID string, vk []byte) ([]byte, error) {
	nonce, err := unb64(v.SealedPrivateKey.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := unb64(v.SealedPrivateKey.Ciphertext)
	if err != nil {
		return nil, err
	}
	key, err := openRaw(vk, nonce, ct, privateKeyAAD(userID, v.SealedPrivateKey.AADVersion))
	if err != nil {
		return nil, err
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("vault: private key has length %d", len(key))
	}
	return key, nil
}

// RewrapPassword replaces the password envelope with one for newPassword. It
// does not bump the vault version; the caller signs and writes the new record.
func (v *Vault) RewrapPassword(userID string, vk []byte, newPassword string) error {
	env := v.findEnvelope(TypePassword)
	if env == nil {
		return ErrEnvelopeNotFound
	}
	salt, err := randomBytes(SaltSize)
	if err != nil {
		return err
	}
	params := DefaultKDFParams()
	kek := argon2.IDKey([]byte(newPassword), salt, params.T, params.M, params.P, KeySize)
	nonce, ct, err := sealRaw(kek, vk, envelopeAAD(userID, env.ID, env.Type, env.CredentialID, env.AADVersion))
	if err != nil {
		return err
	}
	env.Salt = b64(salt)
	env.Params = &params
	env.Nonce = b64(nonce)
	env.Ciphertext = b64(ct)
	return nil
}

// AddRecoveryEnvelope adds another recovery envelope for the same VK.
func (v *Vault) AddRecoveryEnvelope(userID string, vk, recoveryKey []byte) (string, error) {
	env, err := makeRecoveryEnvelope(userID, recoveryKey, vk)
	if err != nil {
		return "", err
	}
	v.Envelopes = append(v.Envelopes, env)
	return env.ID, nil
}

// AddPasskeyEnvelope adds a passkey envelope for a PRF output.
func (v *Vault) AddPasskeyEnvelope(userID string, vk, prf []byte, credentialID string) (string, error) {
	if credentialID == "" {
		return "", fmt.Errorf("vault: credential id is required")
	}
	env, err := makePasskeyEnvelope(userID, prf, vk, credentialID)
	if err != nil {
		return "", err
	}
	v.Envelopes = append(v.Envelopes, env)
	return env.ID, nil
}

// RotateRecoveryKey generates a new recovery key and appends its envelope. The
// caller shows the encoded key, and only then removes the old envelopes.
func (v *Vault) RotateRecoveryKey(userID string, vk []byte) (encodedKey, envelopeID string, err error) {
	key, err := randomBytes(KeySize)
	if err != nil {
		return "", "", err
	}
	id, err := v.AddRecoveryEnvelope(userID, vk, key)
	if err != nil {
		return "", "", err
	}
	return EncodeRecoveryKey(key), id, nil
}

// RemoveRecoveryEnvelopesExcept removes every recovery envelope whose ID is not
// keepID. It is used to retire the old key after a rotation is confirmed.
func (v *Vault) RemoveRecoveryEnvelopesExcept(keepID string) (int, error) {
	found := false
	for i := range v.Envelopes {
		if v.Envelopes[i].ID == keepID && v.Envelopes[i].Type == TypeRecovery {
			found = true
			break
		}
	}
	if !found {
		return 0, ErrEnvelopeNotFound
	}
	kept := v.Envelopes[:0]
	removed := 0
	for _, env := range v.Envelopes {
		if env.Type == TypeRecovery && env.ID != keepID {
			removed++
			continue
		}
		kept = append(kept, env)
	}
	v.Envelopes = kept
	return removed, nil
}

// RemoveEnvelope removes an envelope under the recovery policy.
func (v *Vault) RemoveEnvelope(id string) error {
	idx := -1
	for i := range v.Envelopes {
		if v.Envelopes[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ErrEnvelopeNotFound
	}
	if len(v.Envelopes) == 1 {
		return fmt.Errorf("%w: cannot remove the only envelope", ErrPolicy)
	}
	target := v.Envelopes[idx]
	remainingInvisible := 0
	for i, env := range v.Envelopes {
		if i == idx {
			continue
		}
		if env.Type == TypeRecovery || env.Type == TypePasskey {
			remainingInvisible++
		}
	}
	if target.Type == TypePassword && !v.RecoveryConfirmed {
		return fmt.Errorf("%w: recovery must be confirmed before removing the password", ErrPolicy)
	}
	if v.RecoveryConfirmed && remainingInvisible == 0 {
		return fmt.Errorf("%w: would leave no server-invisible factor", ErrPolicy)
	}
	v.Envelopes = append(v.Envelopes[:idx], v.Envelopes[idx+1:]...)
	return nil
}

// EnvelopeTypes returns the sorted envelope types for display.
func (v *Vault) EnvelopeTypes() []string {
	types := make([]string, 0, len(v.Envelopes))
	for _, env := range v.Envelopes {
		types = append(types, env.Type)
	}
	sort.Strings(types)
	return types
}

// BumpVersion increments the optimistic-concurrency version.
func (v *Vault) BumpVersion() { v.VaultVersion++ }

// ConfirmRecovery marks the recovery key as saved.
func (v *Vault) ConfirmRecovery() { v.RecoveryConfirmed = true }

// ProofPayload is the canonical byte string signed by the vault proof. The
// server reproduces this exact layout before verifying the signature.
func (v *Vault) ProofPayload(userID string) string {
	var b strings.Builder
	b.WriteString("as-vault-proof-v1\n")
	fmt.Fprintf(&b, "user:%s\n", userID)
	fmt.Fprintf(&b, "version:%d\n", v.VaultVersion)
	fmt.Fprintf(&b, "private_key:%s\n", sha256Hex(v.SealedPrivateKey.Ciphertext))
	if v.Bridge != nil {
		fmt.Fprintf(&b, "bridge:%s\n", sha256Hex(v.Bridge.Ciphertext))
	}
	envs := make([]Envelope, len(v.Envelopes))
	copy(envs, v.Envelopes)
	sort.Slice(envs, func(i, j int) bool { return envs[i].ID < envs[j].ID })
	for _, env := range envs {
		fmt.Fprintf(&b, "envelope:%s:%s:%s\n", env.ID, env.Type, sha256Hex(env.Ciphertext))
	}
	return b.String()
}

// Sign derives an Ed25519 key from the VK and signs the envelope set.
func (v *Vault) Sign(userID string, vk []byte) error {
	seed, err := hkdfKey(vk, nil, "as:v1/vault-sign")
	if err != nil {
		return err
	}
	private := ed25519.NewKeyFromSeed(seed)
	v.VaultPubKey = b64(private.Public().(ed25519.PublicKey))
	nonce, err := randomBytes(16)
	if err != nil {
		return err
	}
	v.Proof = &Proof{
		Signature: b64(ed25519.Sign(private, []byte(v.ProofPayload(userID)))),
		Timestamp: time.Now().Unix(),
		Nonce:     b64(nonce),
	}
	return nil
}

// Verify checks the stored proof against the stored vault public key.
func (v *Vault) Verify(userID string) error {
	if v.Proof == nil {
		return fmt.Errorf("%w: missing proof", ErrProof)
	}
	public, err := unb64(v.VaultPubKey)
	if err != nil {
		return err
	}
	if len(public) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad public key size", ErrProof)
	}
	signature, err := unb64(v.Proof.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(public), []byte(v.ProofPayload(userID)), signature) {
		return ErrProof
	}
	return nil
}

// PinPublicKey rejects a vault whose proof key differs from the one pinned on
// this device.
func (v *Vault) PinPublicKey(pinned string) error {
	if pinned == "" {
		return nil
	}
	if v.VaultPubKey != pinned {
		return fmt.Errorf("%w: vault public key changed", ErrProof)
	}
	return nil
}

// Validate checks the record structure before it is uploaded.
func (v *Vault) Validate() error {
	if v.Version != Version {
		return ErrVersion
	}
	if v.VaultVersion < 1 {
		return fmt.Errorf("%w: vault version must be positive", ErrVersion)
	}
	if v.VaultPubKey == "" {
		return fmt.Errorf("%w: missing vault public key", ErrVersion)
	}
	if len(v.Envelopes) == 0 {
		return fmt.Errorf("%w: no envelopes", ErrVersion)
	}
	if v.SealedPrivateKey.Nonce == "" || v.SealedPrivateKey.Ciphertext == "" {
		return fmt.Errorf("%w: missing sealed private key", ErrVersion)
	}
	seen := make(map[string]bool, len(v.Envelopes))
	hasInvisible := false
	for i := range v.Envelopes {
		env := &v.Envelopes[i]
		if env.ID == "" || seen[env.ID] {
			return fmt.Errorf("%w: duplicate or empty envelope id", ErrVersion)
		}
		seen[env.ID] = true
		if env.AADVersion != AADVersion {
			return fmt.Errorf("%w: unsupported AAD version %d", ErrVersion, env.AADVersion)
		}
		if env.Salt == "" || env.Nonce == "" || env.Ciphertext == "" {
			return fmt.Errorf("%w: envelope %q is missing ciphertext fields", ErrVersion, env.ID)
		}
		if _, err := unb64(env.Salt); err != nil {
			return err
		}
		if _, err := unb64(env.Nonce); err != nil {
			return err
		}
		if _, err := unb64(env.Ciphertext); err != nil {
			return err
		}
		switch env.Type {
		case TypePassword:
			if env.KDF != KDFArgon2 {
				return fmt.Errorf("%w: password envelope KDF %q", ErrVersion, env.KDF)
			}
			if _, err := env.kdfParams(); err != nil {
				return err
			}
		case TypeRecovery:
			hasInvisible = true
			if env.KDF != KDFHKDF {
				return fmt.Errorf("%w: recovery envelope KDF %q", ErrVersion, env.KDF)
			}
		case TypePasskey:
			hasInvisible = true
			if env.KDF != KDFHKDF || env.CredentialID == "" {
				return fmt.Errorf("%w: invalid passkey envelope", ErrVersion)
			}
		default:
			return fmt.Errorf("%w: unknown envelope type %q", ErrVersion, env.Type)
		}
	}
	if v.RecoveryConfirmed && !hasInvisible {
		return fmt.Errorf("%w: recovery confirmed without a recovery factor", ErrVersion)
	}
	if v.Bridge != nil {
		if v.Bridge.KDF != KDFHKDF {
			return fmt.Errorf("%w: bridge KDF %q", ErrVersion, v.Bridge.KDF)
		}
		if v.Bridge.Salt == "" || v.Bridge.Nonce == "" || v.Bridge.Ciphertext == "" {
			return fmt.Errorf("%w: bridge is missing ciphertext fields", ErrVersion)
		}
		if _, err := unb64(v.Bridge.Salt); err != nil {
			return err
		}
		if _, err := unb64(v.Bridge.Nonce); err != nil {
			return err
		}
		if _, err := unb64(v.Bridge.Ciphertext); err != nil {
			return err
		}
	}
	return nil
}

var recoveryEncoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// EncodeRecoveryKey renders a 32-byte recovery key as 8 groups of 7 Crockford
// base32 characters, with a 4-character checksum.
func EncodeRecoveryKey(key []byte) string {
	sum := sha256.Sum256(key)
	raw := recoveryEncoding.EncodeToString(key) + recoveryEncoding.EncodeToString(sum[:2])
	var groups []string
	for i := 0; i < len(raw); i += 7 {
		end := i + 7
		if end > len(raw) {
			end = len(raw)
		}
		groups = append(groups, raw[i:end])
	}
	return strings.Join(groups, "-")
}

// DecodeRecoveryKey normalizes and verifies the human-readable recovery key.
func DecodeRecoveryKey(encoded string) ([]byte, error) {
	normalized := strings.ToUpper(strings.TrimSpace(encoded))
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, " ", "")
	normalized = strings.NewReplacer("I", "1", "L", "1", "O", "0").Replace(normalized)
	if len(normalized) != 56 {
		return nil, fmt.Errorf("vault: recovery key must be 56 characters, got %d", len(normalized))
	}
	key, err := recoveryEncoding.DecodeString(normalized[:52])
	if err != nil {
		return nil, fmt.Errorf("vault: recovery key: %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("vault: recovery key decoded to %d bytes", len(key))
	}
	sum := sha256.Sum256(key)
	if recoveryEncoding.EncodeToString(sum[:2]) != normalized[52:] {
		return nil, fmt.Errorf("vault: recovery key checksum mismatch")
	}
	return key, nil
}
