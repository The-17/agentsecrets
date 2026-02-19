// Package auth orchestrates the authentication flows (init, login, logout).
//
// This mirrors the Python SecretsCLI's auth.py module.
// It coordinates between the API client, crypto, config, and keyring packages
// to perform the full authentication lifecycle.
//
// The key function is PerformLogin — used by both init (signup) and login flows.
// It handles: API auth → key decryption → credential storage → workspace caching.
package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/keyring"
)

// Service provides authentication operations.
// It wires together the API client, crypto, config, and keyring packages.
type Service struct {
	API *api.Client
}

// NewService creates a new auth service with the given API client.
func NewService(apiClient *api.Client) *Service {
	return &Service{API: apiClient}
}

// SignupRequest contains the information needed to create a new account.
type SignupRequest struct {
	FirstName string
	LastName  string
	Email     string
	Password  string
}

// Signup creates a new user account and performs auto-login.
//
// Flow:
//  1. Generate keypair + encrypt private key (crypto.SetupUser)
//  2. Send registration to API
//  3. Auto-login with PerformLogin (passing the keypair to skip decryption)
func (s *Service) Signup(req SignupRequest) error {
	// Generate keys
	keys, err := crypto.SetupUser(req.Password)
	if err != nil {
		return fmt.Errorf("signup: %w", err)
	}

	// Build API request body
	data := map[string]interface{}{
		"first_name":           req.FirstName,
		"last_name":            req.LastName,
		"email":                req.Email,
		"password":             req.Password,
		"public_key":           base64.StdEncoding.EncodeToString(keys.PublicKey),
		"encrypted_private_key": keys.EncryptedPrivateKey, // Already base64
		"key_salt":             keys.Salt,                 // Hex string
		"terms_agreement":      true,
	}

	resp, err := s.API.Call("auth.signup", "POST", data, nil)
	if err != nil {
		return fmt.Errorf("signup: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return parseAPIError(resp, "signup")
	}

	// Auto-login after signup — pass the keypair so we skip decryption
	return s.PerformLogin(req.Email, req.Password, keys.PrivateKey, keys.PublicKey)
}

// PerformLogin completes the login flow: authenticate, decrypt keys, store credentials.
//
// This is the heart of the auth system — used by both signup (via auto-login)
// and the login command.
//
// Parameters:
//   - email, password: user credentials
//   - privateKey, publicKey: if provided (signup flow), skip key decryption.
//     If nil (login flow), decrypt from the API response.
//
// Flow:
//  1. Call API login → get tokens + encrypted keys + workspaces
//  2. If no keypair: derive key from password → decrypt private key
//  3. Store email + tokens + keypair
//  4. Decrypt all workspace keys → cache in config
//  5. Set personal workspace as default
func (s *Service) PerformLogin(email, password string, privateKey, publicKey []byte) error {
	// 1. Authenticate with API
	resp, err := s.API.Call("auth.login", "POST", map[string]string{
		"email":    email,
		"password": password,
	}, nil)
	if err != nil {
		return fmt.Errorf("login: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return parseAPIError(resp, "login")
	}

	// Parse response
	var loginResp loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return fmt.Errorf("login: failed to parse response: %w", err)
	}

	// 2. If no keypair provided (login flow), decrypt from server response
	if privateKey == nil {
		encPrivKey := loginResp.Data.EncryptedPrivateKey
		salt := loginResp.Data.KeySalt
		pubKeyB64 := loginResp.Data.User.PublicKey

		if encPrivKey == "" || salt == "" || pubKeyB64 == "" {
			return fmt.Errorf("login: encryption keys missing from server response")
		}

		// Decrypt private key using password
		privateKey, err = crypto.DecryptPrivateKey(encPrivKey, password, salt)
		if err != nil {
			return fmt.Errorf("login: %w", err)
		}

		// Decode public key from response
		publicKey, err = base64.StdEncoding.DecodeString(pubKeyB64)
		if err != nil {
			return fmt.Errorf("login: invalid public key in response: %w", err)
		}
	}

	// 3. Store credentials
	if err := config.SetEmail(email); err != nil {
		return fmt.Errorf("login: failed to save email: %w", err)
	}

	accessToken := coalesce(loginResp.AccessToken, loginResp.Data.Access)
	refreshToken := coalesce(loginResp.RefreshToken, loginResp.Data.Refresh)
	expiresAt := coalesce(loginResp.ExpiresAt, loginResp.Data.ExpiresAt)

	if err := config.StoreTokens(accessToken, refreshToken, expiresAt); err != nil {
		return fmt.Errorf("login: failed to save tokens: %w", err)
	}

	if err := keyring.StoreKeypair(email, privateKey, publicKey); err != nil {
		return fmt.Errorf("login: failed to save keypair: %w", err)
	}

	// 4. Decrypt and cache all workspace keys
	workspaceCache := make(map[string]config.WorkspaceCacheEntry)

	for _, ws := range loginResp.Data.Workspaces {
		encryptedWsKey, err := base64.StdEncoding.DecodeString(ws.EncryptedWorkspaceKey)
		if err != nil {
			continue // Skip this workspace on decode error
		}

		wsKey, err := crypto.DecryptFromUser(privateKey, publicKey, encryptedWsKey)
		if err != nil {
			continue // Skip this workspace on decrypt error
		}

		workspaceCache[ws.ID] = config.WorkspaceCacheEntry{
			Name: ws.Name,
			Key:  base64.StdEncoding.EncodeToString(wsKey),
			Role: ws.Role,
			Type: ws.Type,
		}
	}

	if len(workspaceCache) > 0 {
		if err := config.StoreWorkspaceCache(workspaceCache); err != nil {
			return fmt.Errorf("login: failed to cache workspace keys: %w", err)
		}

		// 5. Set personal workspace as default (if no workspace already selected)
		if config.GetSelectedWorkspaceID() == "" {
			for id, ws := range workspaceCache {
				if ws.Type == "personal" {
					_ = config.SetSelectedWorkspaceID(id)
					break
				}
			}
			// Fallback: use first workspace if no personal found
			if config.GetSelectedWorkspaceID() == "" {
				for id := range workspaceCache {
					_ = config.SetSelectedWorkspaceID(id)
					break
				}
			}
		}
	}

	return nil
}

// Logout clears all stored credentials and invalidates the server session.
func (s *Service) Logout() error {
	email := config.GetEmail()

	// Best-effort: tell server to invalidate tokens
	_, _ = s.API.Call("auth.logout", "POST", nil, nil)

	// Clear keyring
	if email != "" {
		_ = keyring.DeleteKeypair(email)
	}

	// Clear config files
	return config.ClearSession()
}

// --- Response types for JSON parsing ---

// loginResponse matches the API's login response shape.
// The API has inconsistent field locations, so we check multiple paths.
type loginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    string    `json:"expires_at"`
	Data         loginData `json:"data"`
}

type loginData struct {
	Access              string              `json:"access"`
	Refresh             string              `json:"refresh"`
	ExpiresAt           string              `json:"expires_at"`
	EncryptedPrivateKey string              `json:"encrypted_private_key"`
	KeySalt             string              `json:"key_salt"`
	User                loginUser           `json:"user"`
	Workspaces          []loginWorkspace    `json:"workspaces"`
}

type loginUser struct {
	PublicKey string `json:"public_key"`
	Email     string `json:"email"`
}

type loginWorkspace struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	EncryptedWorkspaceKey string `json:"encrypted_workspace_key"`
	Role                  string `json:"role"`
	Type                  string `json:"type"`
}

// --- Helpers ---

// parseAPIError extracts an error message from an API error response.
func parseAPIError(resp *http.Response, context string) error {
	body, _ := io.ReadAll(resp.Body)
	var errResp struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Message != "" {
		return fmt.Errorf("%s failed: %s", context, errResp.Message)
	}
	return fmt.Errorf("%s failed: HTTP %d", context, resp.StatusCode)
}

// coalesce returns the first non-empty string.
func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
