package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/vault"
)

// LoginResult reports what happened to the vault during login or signup.
// RecoveryKey is non-empty only when a new vault was created and the key has
// not been shown before. It must be displayed once and never persisted.
type LoginResult struct {
	RecoveryKey  string
	VaultVersion int
	VaultCreated bool
	Warnings     []string
}

type vaultEnvelope struct {
	Vault        json.RawMessage `json:"vault"`
	VaultVersion int             `json:"vault_version"`
}

// decodeVault parses, structurally validates, and verifies a server vault.
// It also enforces the per-device proof-key pin.
func decodeVault(raw json.RawMessage, userID string) (*vault.Vault, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var v vault.Vault
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("vault: parse: %w", err)
	}
	if err := v.Validate(); err != nil {
		return nil, err
	}
	if err := v.Verify(userID); err != nil {
		return nil, err
	}
	if err := v.PinPublicKey(config.GetVaultPubKey()); err != nil {
		return nil, err
	}
	return &v, nil
}

// loginVault parses the vault returned by the login response. It returns a nil
// record when the server has not stored one yet.
func (s *Service) loginVault(data loginData, userID string) (*vault.Vault, int, error) {
	if len(data.Vault) == 0 || string(data.Vault) == "null" {
		return nil, 0, nil
	}
	if userID == "" {
		return nil, 0, fmt.Errorf("login: server returned a vault without an account id")
	}
	v, err := decodeVault(data.Vault, userID)
	if err != nil {
		return nil, 0, fmt.Errorf("login: %w", err)
	}
	version := data.VaultVersion
	if v != nil && version == 0 {
		version = v.VaultVersion
	}
	return v, version, nil
}

// fetchVault reads the vault record. supported is false when the server has no
// vault endpoint yet, which lets old servers keep working during rollout.
func (s *Service) fetchVault(userID string) (v *vault.Vault, version int, supported bool, err error) {
	resp, err := s.API.Call("auth.vault", "GET", nil, nil, nil)
	if err != nil {
		return nil, 0, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return nil, 0, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, true, s.API.DecodeError(resp)
	}

	var env struct {
		Data vaultEnvelope `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, 0, true, fmt.Errorf("vault: parse response: %w", err)
	}
	v, err = decodeVault(env.Data.Vault, userID)
	if err != nil {
		return nil, 0, true, err
	}
	version = env.Data.VaultVersion
	if v != nil && version == 0 {
		version = v.VaultVersion
	}
	return v, version, true, nil
}

func (s *Service) putVault(v *vault.Vault, expectedVersion int) error {
	return s.API.CallNoContent("auth.vault", "PUT", map[string]interface{}{
		"expected_version": expectedVersion,
		"vault":            v,
	}, nil, nil, http.StatusOK)
}

func (s *Service) pinVault(v *vault.Vault) error {
	if v == nil || v.VaultPubKey == "" {
		return nil
	}
	if config.GetVaultPubKey() == v.VaultPubKey {
		return nil
	}
	return config.SetVaultPubKey(v.VaultPubKey)
}

// unlockLoginKey prefers the vault, then the legacy blob, and finally tries the
// bridge so a password change made by an old client is healed. bridgeVK is set
// only when the legacy key opened the bridge and the password envelope is stale.
func (s *Service) unlockLoginKey(userID, password string, record *vault.Vault, encPrivKey, salt string) (privateKey []byte, fromVault bool, bridgeVK []byte, err error) {
	if record != nil {
		hasPassword, hasPasskey := false, false
		for _, envelopeType := range record.EnvelopeTypes() {
			switch envelopeType {
			case vault.TypePassword:
				hasPassword = true
			case vault.TypePasskey:
				hasPasskey = true
			}
		}
		if !hasPassword && hasPasskey {
			return nil, false, nil, fmt.Errorf("login: this account requires a passkey, which this CLI version does not support yet")
		}
		if vk, uerr := record.UnlockWithPassword(userID, password); uerr == nil {
			pk, perr := record.PrivateKey(userID, vk)
			if perr != nil {
				return nil, false, nil, fmt.Errorf("login: vault: %w", perr)
			}
			return pk, true, nil, nil
		}
	}

	if encPrivKey == "" || salt == "" {
		if record != nil {
			return nil, false, nil, fmt.Errorf("login: vault password envelope failed and legacy key material is missing")
		}
		return nil, false, nil, fmt.Errorf("login: encryption keys missing from server response")
	}

	privateKey, err = crypto.DecryptPrivateKey(encPrivKey, password, salt)
	if err != nil {
		return nil, false, nil, fmt.Errorf("login: %w", err)
	}
	if record != nil {
		if vk, berr := record.UnlockWithBridge(userID, privateKey); berr == nil {
			return privateKey, false, vk, nil
		}
	}
	return privateKey, false, nil, nil
}

type vaultLoginState struct {
	UserID     string
	Password   string
	PrivateKey []byte
	Record     *vault.Vault
	Version    int
	FromVault  bool
	BridgeVK   []byte
	Result     *LoginResult
}

// ensureVault creates a vault for a migrated account, heals a stale password
// envelope through the bridge, or records the existing vault version. Failures
// are warnings because the legacy key path still lets the user work.
func (s *Service) ensureVault(state *vaultLoginState) error {
	if state.UserID == "" {
		state.Result.Warnings = append(state.Result.Warnings, "server did not return an account id; vault setup skipped")
		return nil
	}
	if state.Record != nil {
		if state.FromVault {
			state.Result.VaultVersion = state.Version
			return s.pinVault(state.Record)
		}
		if state.BridgeVK != nil {
			state.Record.BumpVersion()
			if err := state.Record.Sign(state.UserID, state.BridgeVK); err != nil {
				state.Result.Warnings = append(state.Result.Warnings, fmt.Sprintf("vault repair sign failed: %v", err))
				return nil
			}
			if err := s.putVault(state.Record, state.Version); err != nil {
				state.Result.Warnings = append(state.Result.Warnings, fmt.Sprintf("vault repair upload failed: %v", err))
				return nil
			}
			state.Result.VaultVersion = state.Record.VaultVersion
			return s.pinVault(state.Record)
		}
		state.Result.Warnings = append(state.Result.Warnings, "vault exists but no envelope matched this login; the legacy key was used")
		return nil
	}

	existing, version, supported, err := s.fetchVault(state.UserID)
	if err != nil {
		state.Result.Warnings = append(state.Result.Warnings, fmt.Sprintf("vault check failed: %v", err))
		return nil
	}
	if !supported {
		state.Result.Warnings = append(state.Result.Warnings, "server does not support vault storage yet; the account remains on the legacy key")
		return nil
	}
	if existing != nil {
		if vk, uerr := existing.UnlockWithPassword(state.UserID, state.Password); uerr == nil {
			if pk, perr := existing.PrivateKey(state.UserID, vk); perr == nil && bytes.Equal(pk, state.PrivateKey) {
				state.Result.VaultVersion = version
				return s.pinVault(existing)
			}
		}
		// Another device changed the password. Heal the stale envelope
		// through the bridge and re-wrap it under this password.
		bridgeVK, berr := existing.UnlockWithBridge(state.UserID, state.PrivateKey)
		if berr != nil {
			state.Result.Warnings = append(state.Result.Warnings, "the vault on the server does not match this account key; login continued on the legacy key")
			return nil
		}
		if err := existing.RewrapPassword(state.UserID, bridgeVK, state.Password); err != nil {
			state.Result.Warnings = append(state.Result.Warnings, fmt.Sprintf("vault password re-wrap failed: %v", err))
			return nil
		}
		existing.BumpVersion()
		if err := existing.Sign(state.UserID, bridgeVK); err != nil {
			state.Result.Warnings = append(state.Result.Warnings, fmt.Sprintf("vault repair sign failed: %v", err))
			return nil
		}
		if err := s.putVault(existing, version); err != nil {
			state.Result.Warnings = append(state.Result.Warnings, fmt.Sprintf("vault repair upload failed: %v", err))
			return nil
		}
		state.Result.VaultVersion = existing.VaultVersion
		return s.pinVault(existing)
	}

	v, material, err := vault.Create(state.UserID, state.Password, state.PrivateKey)
	if err != nil {
		state.Result.Warnings = append(state.Result.Warnings, fmt.Sprintf("vault create failed: %v", err))
		return nil
	}
	if err := s.putVault(v, 0); err != nil {
		state.Result.Warnings = append(state.Result.Warnings, fmt.Sprintf("vault upload failed: %v", err))
		return nil
	}
	state.Result.RecoveryKey = vault.EncodeRecoveryKey(material.RecoveryKey)
	state.Result.VaultCreated = true
	state.Result.VaultVersion = v.VaultVersion
	return s.pinVault(v)
}

// ConfirmRecovery marks the recovery key as saved after the user proves they
// stored it. The password is used only to unlock the vault in memory.
func (s *Service) ConfirmRecovery(password string) error {
	userID := config.GetUserID()
	if userID == "" {
		return fmt.Errorf("confirm recovery: no account id stored; log in again")
	}
	v, version, supported, err := s.fetchVault(userID)
	if err != nil {
		return err
	}
	if !supported || v == nil {
		return fmt.Errorf("confirm recovery: no vault is available for this account")
	}
	if v.RecoveryConfirmed {
		return nil
	}
	vk, err := v.UnlockWithPassword(userID, password)
	if err != nil {
		return fmt.Errorf("confirm recovery: %w", err)
	}
	v.ConfirmRecovery()
	v.BumpVersion()
	if err := v.Sign(userID, vk); err != nil {
		return fmt.Errorf("confirm recovery: %w", err)
	}
	if err := s.putVault(v, version); err != nil {
		return fmt.Errorf("confirm recovery: %w", err)
	}
	return s.pinVault(v)
}

// VaultStatus is metadata only. It never unlocks the vault.
type VaultStatus struct {
	Supported bool
	Version   int
	Confirmed bool
	Envelopes []string
}

// Status reports the vault envelope types for the status command.
func (s *Service) VaultStatus() (*VaultStatus, error) {
	userID := config.GetUserID()
	if userID == "" {
		return nil, fmt.Errorf("vault status: no account id stored; log in again")
	}
	v, version, supported, err := s.fetchVault(userID)
	if err != nil {
		return nil, err
	}
	if !supported {
		return &VaultStatus{Supported: false}, nil
	}
	if v == nil {
		return &VaultStatus{Supported: true}, nil
	}
	return &VaultStatus{
		Supported: true,
		Version:   version,
		Confirmed: v.RecoveryConfirmed,
		Envelopes: v.EnvelopeTypes(),
	}, nil
}

// RecoveryRotation carries the in-memory state between showing a new recovery
// key and retiring the old one. VK and the vault never leave the process.
type RecoveryRotation struct {
	Key        string
	EnvelopeID string
	UserID     string
	VK         []byte
	Version    int
	Vault      *vault.Vault
}

// BeginRecoveryRotation adds a new recovery envelope and uploads it. The old
// key stays valid until FinishRecoveryRotation is called.
func (s *Service) BeginRecoveryRotation(password string) (*RecoveryRotation, error) {
	userID := config.GetUserID()
	if userID == "" {
		return nil, fmt.Errorf("rotate recovery: no account id stored; log in again")
	}
	v, version, supported, err := s.fetchVault(userID)
	if err != nil {
		return nil, err
	}
	if !supported || v == nil {
		return nil, fmt.Errorf("rotate recovery: no vault is available for this account")
	}
	vk, err := v.UnlockWithPassword(userID, password)
	if err != nil {
		return nil, fmt.Errorf("rotate recovery: %w", err)
	}
	key, id, err := v.RotateRecoveryKey(userID, vk)
	if err != nil {
		return nil, fmt.Errorf("rotate recovery: %w", err)
	}
	v.BumpVersion()
	if err := v.Sign(userID, vk); err != nil {
		return nil, fmt.Errorf("rotate recovery: %w", err)
	}
	if err := s.putVault(v, version); err != nil {
		return nil, fmt.Errorf("rotate recovery: %w", err)
	}
	return &RecoveryRotation{
		Key:        key,
		EnvelopeID: id,
		UserID:     userID,
		VK:         vk,
		Version:    v.VaultVersion,
		Vault:      v,
	}, nil
}

// FinishRecoveryRotation retires every recovery envelope except the new one.
func (s *Service) FinishRecoveryRotation(rot *RecoveryRotation) error {
	if rot == nil || rot.Vault == nil {
		return fmt.Errorf("rotate recovery: missing rotation state")
	}
	if _, err := rot.Vault.RemoveRecoveryEnvelopesExcept(rot.EnvelopeID); err != nil {
		return fmt.Errorf("rotate recovery: %w", err)
	}
	rot.Vault.BumpVersion()
	if err := rot.Vault.Sign(rot.UserID, rot.VK); err != nil {
		return fmt.Errorf("rotate recovery: %w", err)
	}
	if err := s.putVault(rot.Vault, rot.Version); err != nil {
		return fmt.Errorf("rotate recovery: %w", err)
	}
	return nil
}
