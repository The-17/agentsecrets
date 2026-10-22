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
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/keyring"
)

// NewAuthenticatedClient returns a new api.Client configured with dynamic token refresh callback.
func NewAuthenticatedClient() *api.Client {
	client := api.NewClient(func() string {
		return config.GetAccessToken()
	})
	authSvc := NewService(client)
	client.SetRefreshTokenCallback(func() (string, error) {
		tokens, err := config.LoadTokens()
		if err != nil || tokens.RefreshToken == "" {
			return "", fmt.Errorf("no refresh token available")
		}
		if err := authSvc.RefreshSession(tokens.RefreshToken); err != nil {
			return "", err
		}
		return config.GetAccessToken(), nil
	})
	return client
}

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
//  4. Create and upload the vault; the result carries the one-time recovery key
func (s *Service) Signup(req SignupRequest) (*LoginResult, error) {
	// Generate keys
	keys, err := crypto.SetupUser(req.Password)
	if err != nil {
		return nil, fmt.Errorf("signup: %w", err)
	}

	// Build API request body
	data := map[string]interface{}{
		"first_name":            req.FirstName,
		"last_name":             req.LastName,
		"email":                 req.Email,
		"password":              req.Password,
		"public_key":            base64.StdEncoding.EncodeToString(keys.PublicKey),
		"encrypted_private_key": keys.EncryptedPrivateKey, // Already base64
		"key_salt":              keys.Salt,                // Hex string
		"terms_agreement":       true,
	}

	if err := s.API.CallNoContent("auth.signup", "POST", data, nil, nil, http.StatusCreated); err != nil {
		return nil, fmt.Errorf("signup: API call failed: %w", err)
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
//  2. If no keypair: unlock the vault, else decrypt the legacy key, else heal via the bridge
//  3. Store email + tokens + keypair
//  4. Create, repair, or pin the vault record
//  5. Decrypt all workspace keys → cache in config
//  6. Set personal workspace as default
func (s *Service) PerformLogin(email, password string, privateKey, publicKey []byte) (*LoginResult, error) {
	// 1. Authenticate. An enrolled account has no password factor, so a
	// password_login_disabled answer means "run the OPAQUE exchange", not
	// "fail". The password still never crosses the wire on that path.
	resp, err := s.API.Call("auth.login", "POST", map[string]string{
		"email":    email,
		"password": password,
	}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("login: API call failed: %w", err)
	}
	defer resp.Body.Close()

	loginResp, err := s.authenticate(email, password, resp)
	if err != nil {
		return nil, err
	}

	result := &LoginResult{}
	userID := (*loginResp).Data.User.ID
	record, recordVersion, err := s.loginVault((*loginResp).Data, userID)
	if err != nil {
		return nil, err
	}
	result.RecoveryConfirmed = record != nil && record.RecoveryConfirmed
	// The OPAQUE finish response carries the derived session key; password
	// login does not. This is how the caller knows not to re-enroll.
	result.OpaqueLogin = (*loginResp).Data.SessionKey != ""

	// 2. If no keypair provided (login flow), unlock from the vault or legacy blob.
	var (
		fromVault bool
		bridgeVK  []byte
	)
	if privateKey == nil {
		privateKey, fromVault, bridgeVK, err = s.unlockLoginKey(
			userID, password, record,
			(*loginResp).Data.EncryptedPrivateKey, (*loginResp).Data.KeySalt,
		)
		if err != nil {
			return nil, err
		}

		pubKeyB64 := (*loginResp).Data.User.PublicKey
		if pubKeyB64 == "" {
			return nil, fmt.Errorf("login: public key missing from server response")
		}
		publicKey, err = base64.StdEncoding.DecodeString(pubKeyB64)
		if err != nil {
			return nil, fmt.Errorf("login: invalid public key in response: %w", err)
		}
	}

	if err := config.SetEmail(email); err != nil {
		return nil, fmt.Errorf("login: failed to save email: %w", err)
	}
	if userID != "" {
		if err := config.SetUserID(userID); err != nil {
			return nil, fmt.Errorf("login: failed to save account id: %w", err)
		}
	}

	// Compute and store local password hash for allowlist verification
	hasher := sha256.New()
	hasher.Write([]byte(email + ":" + password))
	passwordHash := hex.EncodeToString(hasher.Sum(nil))

	globalCfg, _ := config.LoadGlobalConfig()
	if globalCfg == nil {
		globalCfg = &config.GlobalConfig{}
	}
	globalCfg.Email = email
	globalCfg.PasswordHash = passwordHash
	if err := config.SaveGlobalConfig(globalCfg); err != nil {
		return nil, fmt.Errorf("login: failed to save global config: %w", err)
	}

	accessToken := coalesce((*loginResp).AccessToken, (*loginResp).Data.Access)
	if err := config.StoreTokens(
		accessToken,
		coalesce((*loginResp).RefreshToken, (*loginResp).Data.Refresh),
		coalesce((*loginResp).ExpiresAt, (*loginResp).Data.ExpiresAt),
	); err != nil {
		return nil, fmt.Errorf("login: failed to save tokens: %w", err)
	}

	if err := keyring.StoreKeypair(email, privateKey, publicKey); err != nil {
		return nil, fmt.Errorf("login: failed to save keypair: %w", err)
	}

	// 4. Create a vault for a legacy account, heal a stale envelope, or pin the
	// existing proof key. Failures here are warnings, not login blockers.
	state := &vaultLoginState{
		UserID:     userID,
		Password:   password,
		PrivateKey: privateKey,
		Record:     record,
		Version:    recordVersion,
		FromVault:  fromVault,
		BridgeVK:   bridgeVK,
		Result:     result,
	}
	if err := s.ensureVault(state); err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	// 5. Decrypt and cache all workspace keys
	if err := cacheWorkspaces(privateKey, publicKey, (*loginResp).Data.Workspaces); err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	return result, nil
}

// authenticate returns the server login payload, switching to OPAQUE when the
// account has no password factor.
func (s *Service) authenticate(email, password string, resp *http.Response) (*loginResponse, error) {
	if resp.StatusCode == http.StatusOK {
		var out loginResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil, fmt.Errorf("login: failed to parse response: %w", err)
		}
		return &out, nil
	}

	if s.passwordLoginDisabled(resp) {
		return s.opaqueLogin(email, password)
	}
	return nil, s.API.DecodeError(resp)
}

// passwordLoginDisabled reports whether the server refused because the account
// is enrolled in OPAQUE. Any other failure stays a failure.
func (s *Service) passwordLoginDisabled(resp *http.Response) bool {
	if resp.StatusCode != http.StatusUnauthorized {
		return false
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return bytes.Contains(body, []byte("password_login_disabled"))
}

// cacheWorkspaces decrypts workspace keys and stores them for later commands.
// It selects the personal workspace as default when none is selected.
func cacheWorkspaces(privateKey, publicKey []byte, workspaces []loginWorkspace) error {
	workspaceCache := make(map[string]config.WorkspaceCacheEntry)

	for _, ws := range workspaces {
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

	if len(workspaceCache) == 0 {
		return nil
	}

	if err := config.StoreWorkspaceCache(workspaceCache); err != nil {
		return fmt.Errorf("failed to cache workspace keys: %w", err)
	}

	// Set personal workspace as default (if none selected)
	if config.GetSelectedWorkspaceID() == "" {
		id := ""
		for k, ws := range workspaceCache {
			if id == "" || strings.EqualFold(ws.Type, "personal") {
				id = k
			}
			if strings.EqualFold(ws.Type, "personal") {
				break
			}
		}
		if id != "" {
			_ = config.SetSelectedWorkspaceID(id)
		}
	}

	return nil
}

// Logout clears all stored credentials and invalidates the server session.
func (s *Service) Logout() error {
	email := config.GetEmail()

	// Best-effort: tell server to invalidate tokens
	_, _ = s.API.Call("auth.logout", "POST", nil, nil, nil)

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
	Access              string           `json:"access"`
	Refresh             string           `json:"refresh"`
	ExpiresAt           string           `json:"expires_at"`
	EncryptedPrivateKey string           `json:"encrypted_private_key"`
	KeySalt             string           `json:"key_salt"`
	Vault               json.RawMessage  `json:"vault"`
	VaultVersion        int              `json:"vault_version"`
	SessionKey          string           `json:"session_key"`
	User                loginUser        `json:"user"`
	Workspaces          []loginWorkspace `json:"workspaces"`
}

type loginUser struct {
	ID        string `json:"id"`
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

// coalesce returns the first non-empty string.
func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
