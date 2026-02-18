// Package auth orchestrates the authentication flows (init, login, logout).
//
// This mirrors the Python SecretsCLI's auth.py module.
// It coordinates between the API client, crypto, config, and keyring packages
// to perform the full authentication lifecycle.
package auth

// Service provides authentication operations.
// It will be wired up with the API client, crypto, and keyring packages
// once we implement the actual flows.
type Service struct {
	// These will be injected when we implement the real flows:
	// apiClient *api.Client
	// config    *config.GlobalConfig
}

// NewService creates a new auth service.
func NewService() *Service {
	return &Service{}
}

// TODO: Implement these methods:
//
// Signup(email, password string) error
//   1. Generate X25519 keypair
//   2. Derive password key (Argon2id)
//   3. Encrypt private key with password key
//   4. Send to API: email, password, public_key, encrypted_private_key, salt
//   5. Call performLogin to complete
//
// Login(email, password string) error
//   1. Call API login endpoint
//   2. Receive tokens + encrypted_private_key + salt + workspaces
//   3. Derive password key from password + salt
//   4. Decrypt private key
//   5. Decrypt workspace keys using private key
//   6. Store everything (tokens, keypair, workspace cache)
//
// Logout() error
//   1. Delete keypair from keychain
//   2. Clear tokens
//   3. Clear workspace cache
