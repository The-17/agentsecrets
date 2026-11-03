package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/vault"
)

// recoveryChallenge is the unauthenticated challenge response. The server
// returns the vault so the client can unlock it locally; it never returns a key.
type recoveryChallenge struct {
	Data struct {
		Challenge    string          `json:"challenge"`
		Nonce        string          `json:"nonce"`
		ExpiresAt    string          `json:"expires_at"`
		UserID       string          `json:"user_id"`
		Vault        json.RawMessage `json:"vault"`
		VaultVersion int             `json:"vault_version"`
	} `json:"data"`
}

// decodeRecoveryView parses the unauthenticated recovery view. It cannot verify
// the proof because the view omits the envelope set the proof covers. The proof
// is verified against the full vault returned after the signature check.
func decodeRecoveryView(raw json.RawMessage) (*vault.Vault, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fmt.Errorf("vault is missing")
	}
	var v vault.Vault
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("parse vault: %w", err)
	}
	if v.VaultPubKey == "" {
		return nil, fmt.Errorf("vault is missing its proof key")
	}
	if pin := config.GetVaultPubKey(); pin != "" && v.VaultPubKey != pin {
		return nil, fmt.Errorf("vault proof key does not match the pinned key")
	}
	if v.VaultVersion < 1 {
		return nil, fmt.Errorf("vault version is invalid")
	}
	return &v, nil
}

// RecoverAccount restores a session with the recovery key instead of the
// password, then rewraps the vault under newPassword when one is supplied.
//
// The server never sees the recovery key or the vault key. It verifies an
// Ed25519 signature over its own challenge against the pinned vault public key,
// which the client can only produce by unlocking the vault.
func (s *Service) RecoverAccount(email, recoveryKey, newPassword string) (*LoginResult, error) {
	if _, err := vault.DecodeRecoveryKey(recoveryKey); err != nil {
		return nil, fmt.Errorf("recovery: invalid recovery key")
	}

	resp, err := s.API.Call("auth.recover_challenge", "POST", map[string]string{
		"email": email,
	}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("recovery: challenge request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, s.API.DecodeError(resp)
	}

	var challenge recoveryChallenge
	if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
		return nil, fmt.Errorf("recovery: parse challenge: %w", err)
	}
	if challenge.Data.UserID == "" || len(challenge.Data.Vault) == 0 || string(challenge.Data.Vault) == "null" {
		return nil, fmt.Errorf("recovery: no recoverable vault for that account")
	}

	record, err := decodeRecoveryView(challenge.Data.Vault)
	if err != nil {
		return nil, fmt.Errorf("recovery: %w", err)
	}
	if record == nil {
		return nil, fmt.Errorf("recovery: no vault on that account")
	}

	vk, err := record.UnlockWithRecoveryKey(challenge.Data.UserID, recoveryKey)
	if err != nil {
		return nil, fmt.Errorf("recovery: that recovery key does not unlock this account")
	}
	privateKey, err := record.PrivateKey(challenge.Data.UserID, vk)
	if err != nil {
		return nil, fmt.Errorf("recovery: %w", err)
	}
	publicKey, err := crypto.PublicFromPrivate(privateKey)
	if err != nil {
		return nil, fmt.Errorf("recovery: %w", err)
	}

	signature, err := vault.SignChallenge(vk, []byte(challenge.Data.Challenge))
	if err != nil {
		return nil, fmt.Errorf("recovery: sign challenge: %w", err)
	}

	verifyResp, err := s.API.Call("auth.recover_verify", "POST", map[string]string{
		"email":     email,
		"nonce":     challenge.Data.Nonce,
		"signature": base64.StdEncoding.EncodeToString(signature),
	}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("recovery: verification failed: %w", err)
	}
	defer verifyResp.Body.Close()
	if verifyResp.StatusCode != http.StatusOK {
		return nil, s.API.DecodeError(verifyResp)
	}

	var loginResp loginResponse
	if err := json.NewDecoder(verifyResp.Body).Decode(&loginResp); err != nil {
		return nil, fmt.Errorf("recovery: parse response: %w", err)
	}
	userID := loginResp.Data.User.ID
	if userID == "" || userID != challenge.Data.UserID {
		return nil, fmt.Errorf("recovery: server returned a different account")
	}

	// The verify response is authenticated by the signature above, so it may
	// carry the full vault. Verify its proof before rewriting it.
	fullVault, err := decodeVault(loginResp.Data.Vault, userID)
	if err != nil {
		return nil, fmt.Errorf("recovery: %w", err)
	}
	if fullVault == nil {
		return nil, fmt.Errorf("recovery: server returned no vault")
	}
	if fullVault.VaultPubKey != record.VaultPubKey {
		return nil, fmt.Errorf("recovery: vault proof key changed mid-recovery")
	}

	if err := s.storeRecoveredSession(email, userID, loginResp, privateKey, publicKey); err != nil {
		return nil, err
	}

	result := &LoginResult{VaultVersion: fullVault.VaultVersion}

	if newPassword != "" {
		expectedVersion := fullVault.VaultVersion
		// For a v1 vault the password envelope wraps the full VK. For a v2 split
		// vault it wraps the password share k1, which cannot be derived yet
		// (the new OPAQUE export key arrives from re-enrollment below), so the
		// share rotation happens after EnrollOpaque via RotateShares.
		if !fullVault.IsSplit() {
			if err := fullVault.RewrapPassword(userID, vk, newPassword); err != nil {
				return nil, fmt.Errorf("recovery: this account has no password factor to reset")
			}
		}
		// Using the recovery key proves the user has it, so mark recovery
		// confirmed. This is the gate OPAQUE enrollment relies on: enrolling an
		// account whose recovery key was never saved would strand it once the
		// password factor is removed.
		fullVault.ConfirmRecovery()
		fullVault.BumpVersion()
		if err := fullVault.Sign(userID, vk); err != nil {
			return nil, fmt.Errorf("recovery: resign vault: %w", err)
		}

		blob, salt, err := crypto.EncryptPrivateKey(privateKey, newPassword)
		if err != nil {
			return nil, fmt.Errorf("recovery: encrypt private key: %w", err)
		}
		if err := s.API.CallNoContent("auth.recover_password", "PATCH", map[string]interface{}{
			"new_password":          newPassword,
			"key_salt":              salt,
			"encrypted_private_key": blob,
			"vault":                 fullVault,
			"expected_version":      expectedVersion,
		}, nil, nil, http.StatusOK); err != nil {
			return nil, fmt.Errorf("recovery: you are signed in, but the new password was not saved: %w", err)
		}

		if err := saveLocalPasswordHash(email, newPassword); err != nil {
			result.Warnings = append(result.Warnings, "password reset, but the local verification hash could not be saved")
		}
		result.VaultVersion = fullVault.VaultVersion
		result.RecoveryConfirmed = fullVault.RecoveryConfirmed
	}

	// Recovery cleared the server's OPAQUE record and restored the password, so
	// the local flag must be cleared too. Otherwise the login command would see
	// "already enrolled" and never re-enroll, leaving the account password-only.
	if err := config.SetOpaqueEnrolled(false); err != nil {
		result.Warnings = append(result.Warnings, "recovered, but the local OPAQUE flag could not be cleared")
	}

	// Re-enroll OPAQUE now that the account is password-only again. This is
	// gated on a confirmed recovery key and a server that actually runs OPAQUE;
	// a failure leaves the recovered password working.
	if newPassword != "" && result.RecoveryConfirmed && s.ServerSupportsOpaque() {
		exportKey, rerr := s.EnrollOpaque(email, newPassword)
		if rerr != nil {
			result.Warnings = append(result.Warnings, "recovered, but OPAQUE re-enrollment failed: "+rerr.Error())
		} else if fullVault.IsSplit() && len(exportKey) > 0 {
			// The OPAQUE record rotated, so the OPAQUE share must be re-wrapped
			// under the new export key. We hold the full VK (from the recovery
			// key) and the new password, so RotateShares regenerates both shares
			// and re-wraps them. Then bump, sign, and upload.
			if rerr := fullVault.RotateShares(userID, vk, newPassword, exportKey); rerr != nil {
				result.Warnings = append(result.Warnings, "recovered, but the vault OPAQUE share could not be re-wrapped: "+rerr.Error())
			} else {
				fullVault.BumpVersion()
				if serr := fullVault.Sign(userID, vk); serr != nil {
					result.Warnings = append(result.Warnings, "recovered, but the vault proof could not be re-signed: "+serr.Error())
				} else if perr := s.putVault(fullVault, fullVault.VaultVersion-1); perr != nil {
					result.Warnings = append(result.Warnings, "recovered, but the re-wrapped vault could not be saved: "+perr.Error())
				}
			}
		}
	}

	if err := cacheWorkspaces(privateKey, publicKey, loginResp.Data.Workspaces); err != nil {
		return nil, fmt.Errorf("recovery: %w", err)
	}

	return result, nil
}

// storeRecoveredSession persists the credentials from a verified recovery.
func (s *Service) storeRecoveredSession(
	email, userID string,
	loginResp loginResponse,
	privateKey, publicKey []byte,
) error {
	if err := config.SetEmail(email); err != nil {
		return fmt.Errorf("recovery: failed to save email: %w", err)
	}
	if err := config.SetUserID(userID); err != nil {
		return fmt.Errorf("recovery: failed to save account id: %w", err)
	}

	accessToken := coalesce(loginResp.AccessToken, loginResp.Data.Access)
	if err := config.StoreTokens(
		accessToken,
		coalesce(loginResp.RefreshToken, loginResp.Data.Refresh),
		coalesce(loginResp.ExpiresAt, loginResp.Data.ExpiresAt),
	); err != nil {
		return fmt.Errorf("recovery: failed to save tokens: %w", err)
	}

	if err := keyring.StoreKeypair(email, privateKey, publicKey); err != nil {
		return fmt.Errorf("recovery: failed to save keypair: %w", err)
	}
	return nil
}

// saveLocalPasswordHash stores the allowlist verification hash used offline.
func saveLocalPasswordHash(email, password string) error {
	globalCfg, _ := config.LoadGlobalConfig()
	if globalCfg == nil {
		globalCfg = &config.GlobalConfig{}
	}
	globalCfg.Email = email
	globalCfg.PasswordHash = localPasswordHash(email, password)
	return config.SaveGlobalConfig(globalCfg)
}

// localPasswordHash mirrors the local verification hash stored by PerformLogin.
func localPasswordHash(email, password string) string {
	sum := sha256.Sum256([]byte(email + ":" + password))
	return hex.EncodeToString(sum[:])
}
