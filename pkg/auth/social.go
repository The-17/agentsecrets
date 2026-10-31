package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/The-17/agentsecrets/pkg/crypto"
)

// CompleteSocialOnboarding finishes a social (Google/GitHub) sign-in on this
// device. A social sign-in proves identity only: the account has no vault key
// on this machine, and a brand-new social account has no keys at all.
//
// The human supplies the master vault password once, here, so the flow does
// not dead-end in a second `login` command:
//
//   - hasKeys == false (new social account): generate the keypair, seal the
//     private key under the password, and register it via /auth/keys/initialize/.
//     The password becomes the account's password factor.
//   - hasKeys == true (returning account): skip key setup.
//
// Both cases then run PerformLogin, which authenticates with the password,
// unlocks the vault locally, stores the keypair, and caches workspace keys.
// The password never leaves this device.
func (s *Service) CompleteSocialOnboarding(email, password string, hasKeys bool) (*LoginResult, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, fmt.Errorf("social onboarding: no account email available")
	}
	if len(password) < 8 {
		return nil, fmt.Errorf("social onboarding: password must be at least 8 characters")
	}

	if !hasKeys {
		keys, err := crypto.SetupUser(password)
		if err != nil {
			return nil, fmt.Errorf("social onboarding: %w", err)
		}
		data := map[string]interface{}{
			"public_key":            base64.StdEncoding.EncodeToString(keys.PublicKey),
			"encrypted_private_key": keys.EncryptedPrivateKey,
			"key_salt":              keys.Salt,
			"password":              password,
		}
		if err := s.API.CallNoContent("auth.keys_initialize", "POST", data, nil, nil, http.StatusOK); err != nil {
			return nil, fmt.Errorf("social onboarding: key setup failed: %w", err)
		}
	}

	// PerformLogin does the rest: authenticate with the password, unlock the
	// vault, store the keypair, and cache workspace keys.
	result, err := s.PerformLogin(email, password, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("social onboarding: %w", err)
	}
	result.HasKeys = true
	return result, nil
}
