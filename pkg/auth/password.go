package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/keyring"
)

// ChangePassword re-encrypts the legacy blob and the vault password envelope
// with the new password, then updates the server in one request. The private
// key comes from the local keychain, so the current password is only needed for
// the server's check and the vault unwrap.
func (s *Service) ChangePassword(currentPassword, newPassword string) error {
	email := config.GetEmail()
	if email == "" {
		return fmt.Errorf("change password: not logged in")
	}
	privateKey, err := keyring.GetPrivateKey(email)
	if err != nil {
		return fmt.Errorf("change password: %w", err)
	}

	encrypted, salt, err := crypto.EncryptPrivateKey(privateKey, newPassword)
	if err != nil {
		return fmt.Errorf("change password: %w", err)
	}
	body := map[string]interface{}{
		"current_password":      currentPassword,
		"new_password":          newPassword,
		"key_salt":              salt,
		"encrypted_private_key": encrypted,
	}

	userID := config.GetUserID()
	if userID != "" {
		v, version, supported, err := s.fetchVault(userID)
		if err != nil {
			return fmt.Errorf("change password: %w", err)
		}
		if supported && v != nil {
			vk, err := v.UnlockWithPassword(userID, currentPassword)
			if err != nil {
				// An old client may have changed the password and left the
				// password envelope stale. The bridge is the fallback.
				vk, err = v.UnlockWithBridge(userID, privateKey)
				if err != nil {
					return fmt.Errorf("change password: cannot unlock the vault with the current password or the private-key bridge: %w", err)
				}
			}
			if err := v.RewrapPassword(userID, vk, newPassword); err != nil {
				return fmt.Errorf("change password: %w", err)
			}
			v.BumpVersion()
			if err := v.Sign(userID, vk); err != nil {
				return fmt.Errorf("change password: %w", err)
			}
			body["vault"] = v
			body["expected_version"] = version
		}
	}

	if err := s.API.CallNoContent("auth.change_password", "PATCH", body, nil, nil, http.StatusOK); err != nil {
		return fmt.Errorf("change password: %w", err)
	}

	hasher := sha256.New()
	hasher.Write([]byte(email + ":" + newPassword))
	passwordHash := hex.EncodeToString(hasher.Sum(nil))

	globalCfg, _ := config.LoadGlobalConfig()
	if globalCfg == nil {
		globalCfg = &config.GlobalConfig{}
	}
	globalCfg.PasswordHash = passwordHash
	if err := config.SaveGlobalConfig(globalCfg); err != nil {
		return fmt.Errorf("change password: %w", err)
	}
	return nil
}
