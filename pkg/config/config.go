// Package config manages all configuration files for AgentSecrets.
//
// This mirrors the Python SecretsCLI's config.py and parts of credentials.py.
//
// File layout:
//
//	~/.agentsecrets/
//	├── config.json     # User email, workspace cache, selected workspace
//	└── token.json      # JWT access/refresh tokens
//
//	./.agentsecrets/
//	└── project.json    # Project binding for current directory
//
// Note: Private key is stored in OS keychain (see pkg/keyring), not in files.
package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/The-17/agentsecrets/pkg/keyring"
)

var (
	cachedProjectConfigMu sync.RWMutex
	cachedProjectConfig   *ProjectConfig
	cachedProjectRoot     string

	cachedTokensMu sync.RWMutex
	cachedTokens   *TokenConfig

	cachedWorkspaceKeysMu sync.RWMutex
	cachedWorkspaceKeys   = make(map[string][]byte)
)

// DefaultServerURL is the default AgentSecrets Server endpoint.
const DefaultServerURL = "https://api.agentsecrets.tech/api"

// GlobalConfig represents ~/.agentsecrets/config.json
type GlobalConfig struct {
	ServerURL           string                         `json:"server_url,omitempty"` // Custom self-hosted server URL (empty defaults to default AgentSecrets Server)
	Email               string                         `json:"email,omitempty"`
	SelectedWorkspaceID string                         `json:"selected_workspace_id,omitempty"`
	SelectedProjectID   string                         `json:"selected_project_id,omitempty"`
	SelectedEnvironment string                         `json:"selected_environment,omitempty"` // "development", "staging", "production"
	Workspaces          map[string]WorkspaceCacheEntry `json:"workspaces,omitempty"`
	PasswordHash        string                         `json:"password_hash,omitempty"` // Added for local password verification
	DefaultStorageMode  int                            `json:"default_storage_mode"`    // 1 = keychain (default), 2 = env_file
	LastUpdateCheck     int64                          `json:"last_update_check,omitempty"`
	LatestVersion       string                         `json:"latest_version,omitempty"`
	LastUpdateAlert     int64                          `json:"last_update_alert,omitempty"`
}

// WorkspaceCacheEntry is a cached workspace with its decrypted key
type WorkspaceCacheEntry struct {
	Name string `json:"name"`
	Key  string `json:"key"`  // Base64-encoded decrypted workspace key
	Role string `json:"role"` // "owner", "admin", "member"
	Type string `json:"type"` // "personal", "shared"
}

// TokenConfig represents ~/.agentsecrets/token.json
type TokenConfig struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
}

// ProjectConfig represents ./.agentsecrets/project.json
type ProjectConfig struct {
	ServerURL     string `json:"server_url,omitempty"` // Optional project-specific self-hosted server override
	ProjectID     string `json:"project_id"`
	ProjectName   string `json:"project_name"`
	Description   string `json:"description"`
	Environment   string `json:"environment"` // "development", "staging", "production"
	WorkspaceID   string `json:"workspace_id"`
	WorkspaceName string `json:"workspace_name"`
	LastPull      string `json:"last_pull"`
	LastPush      string `json:"last_push"`
	StorageMode   int    `json:"storage_mode"`
}

// ServerTarget describes the resolved server and its configuration source.
type ServerTarget struct {
	URL        string
	Source     string // "flag", "env", "project", "global", "default"
	IsSelfHost bool
}

// NormalizeServerURL validates and normalizes an input server URL.
// Ensures scheme (http/https), strips trailing slashes, and ensures standard /api route prefix.
func NormalizeServerURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultServerURL
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		if strings.HasPrefix(raw, "localhost") || strings.HasPrefix(raw, "127.0.0.1") {
			raw = "http://" + raw
		} else {
			raw = "https://" + raw
		}
	}
	raw = strings.TrimRight(raw, "/")
	u, err := url.Parse(raw)
	if err == nil {
		if u.Path == "" || u.Path == "/" {
			raw = raw + "/api"
		}
	}
	return raw
}

// ResolveServerTarget determines the active server URL and its source.
func ResolveServerTarget(flagOverride string) ServerTarget {
	if flagOverride != "" {
		norm := NormalizeServerURL(flagOverride)
		return ServerTarget{
			URL:        norm,
			Source:     "flag (--server)",
			IsSelfHost: norm != DefaultServerURL,
		}
	}

	if envURL := os.Getenv("AGENTSECRETS_SERVER_URL"); envURL != "" {
		norm := NormalizeServerURL(envURL)
		return ServerTarget{
			URL:        norm,
			Source:     "environment (AGENTSECRETS_SERVER_URL)",
			IsSelfHost: norm != DefaultServerURL,
		}
	}
	if envURL := os.Getenv("AGENTSECRETS_API_URL"); envURL != "" {
		norm := NormalizeServerURL(envURL)
		return ServerTarget{
			URL:        norm,
			Source:     "environment (AGENTSECRETS_API_URL)",
			IsSelfHost: norm != DefaultServerURL,
		}
	}

	// Check project-level config
	if pc, err := LoadProjectConfig(); err == nil && pc != nil && pc.ServerURL != "" {
		norm := NormalizeServerURL(pc.ServerURL)
		return ServerTarget{
			URL:        norm,
			Source:     "project (.agentsecrets/project.json)",
			IsSelfHost: norm != DefaultServerURL,
		}
	}

	// Check global config
	if gc, err := LoadGlobalConfig(); err == nil && gc != nil && gc.ServerURL != "" {
		norm := NormalizeServerURL(gc.ServerURL)
		return ServerTarget{
			URL:        norm,
			Source:     "global (~/.agentsecrets/config.json)",
			IsSelfHost: norm != DefaultServerURL,
		}
	}

	return ServerTarget{
		URL:        DefaultServerURL,
		Source:     "AgentSecrets Server (default)",
		IsSelfHost: false,
	}
}

// GetServerURL returns the active server URL.
func GetServerURL() string {
	return ResolveServerTarget("").URL
}

// SetGlobalServerURL updates the server URL in ~/.agentsecrets/config.json.
func SetGlobalServerURL(serverURL string) error {
	gc, err := LoadGlobalConfig()
	if err != nil {
		gc = &GlobalConfig{}
	}
	gc.ServerURL = NormalizeServerURL(serverURL)
	return SaveGlobalConfig(gc)
}

// ResetGlobalServerURL resets the global server URL back to AgentSecrets Server default.
func ResetGlobalServerURL() error {
	gc, err := LoadGlobalConfig()
	if err != nil {
		return nil
	}
	gc.ServerURL = ""
	return SaveGlobalConfig(gc)
}

// SetProjectServerURL updates the server URL in .agentsecrets/project.json.
func SetProjectServerURL(serverURL string) error {
	pc, err := LoadProjectConfig()
	if err != nil || pc == nil {
		return fmt.Errorf("no project config found in current directory")
	}
	pc.ServerURL = NormalizeServerURL(serverURL)
	return SaveProjectConfig(pc)
}

// Paths returns the standard config file paths
type Paths struct {
	GlobalDir  string // ~/.agentsecrets/
	ConfigFile string // ~/.agentsecrets/config.json
	TokenFile  string // ~/.agentsecrets/token.json
}

// HomeDirHook is used to determine the user's home directory.
// It can be overridden in tests to redirect config files.
var HomeDirHook = os.UserHomeDir

// GetPaths returns the standard config paths based on the user's home directory.
func GetPaths() (*Paths, error) {
	home, err := HomeDirHook()
	if err != nil {
		return nil, fmt.Errorf("could not determine home directory: %w", err)
	}

	globalDir := filepath.Join(home, ".agentsecrets")
	return &Paths{
		GlobalDir:  globalDir,
		ConfigFile: filepath.Join(globalDir, "config.json"),
		TokenFile:  filepath.Join(globalDir, "token.json"),
	}, nil
}

// GlobalConfigExists returns true if ~/.agentsecrets/config.json already exists.
func GlobalConfigExists() bool {
	paths, err := GetPaths()
	if err != nil {
		return false
	}
	_, err = os.Stat(paths.ConfigFile)
	return err == nil
}

// InitGlobalConfig creates the ~/.agentsecrets/ directory and default config files.
func InitGlobalConfig() error {
	paths, err := GetPaths()
	if err != nil {
		return err
	}

	// Create directory
	if err := os.MkdirAll(paths.GlobalDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create config.json if it doesn't exist
	if _, err := os.Stat(paths.ConfigFile); os.IsNotExist(err) {
		if err := writeJSON(paths.ConfigFile, &GlobalConfig{}, 0600); err != nil {
			return err
		}
	}

	// Create token.json with restricted permissions if it doesn't exist
	if _, err := os.Stat(paths.TokenFile); os.IsNotExist(err) {
		if err := writeJSON(paths.TokenFile, &TokenConfig{}, 0600); err != nil {
			return err
		}
	}

	return nil
}

// InitProjectConfig creates .agentsecrets/project.json in the current directory.
func InitProjectConfig(storageMode int) error {
	projectDir := filepath.Join(".", ".agentsecrets")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		return fmt.Errorf("failed to create project config directory: %w", err)
	}

	projectFile := filepath.Join(projectDir, "project.json")
	if _, err := os.Stat(projectFile); os.IsNotExist(err) {
		defaultConfig := &ProjectConfig{
			Environment: "development",
			StorageMode: storageMode,
		}
		if err := writeJSON(projectFile, defaultConfig, 0644); err != nil {
			return err
		}
	} else {
		// Update existing if it exists (for force re-init cases)
		pc, err := LoadProjectConfig()
		if err == nil && pc != nil {
			pc.StorageMode = storageMode
			return SaveProjectConfig(pc)
		}
	}

	return nil
}

// LoadGlobalConfig reads ~/.agentsecrets/config.json
func LoadGlobalConfig() (*GlobalConfig, error) {
	paths, err := GetPaths()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(paths.ConfigFile)
	if err != nil {
		return nil, err
	}

	var config GlobalConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Migration: If default_storage_mode is 0, check for legacy storage_mode key
	if config.DefaultStorageMode == 0 {
		var legacy struct {
			StorageMode int `json:"storage_mode"`
		}
		if err := json.Unmarshal(data, &legacy); err == nil && legacy.StorageMode != 0 {
			config.DefaultStorageMode = legacy.StorageMode
		} else {
			// Ensure it's never 0 (default to 1)
			config.DefaultStorageMode = 1
		}
	}

	return &config, nil
}

// SaveGlobalConfig writes ~/.agentsecrets/config.json
func SaveGlobalConfig(config *GlobalConfig) error {
	paths, err := GetPaths()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(paths.GlobalDir, 0700); err != nil {
		return err
	}
	return writeJSON(paths.ConfigFile, config, 0600)
}

// InvalidateTokenCache clears the in-memory cached tokens.
func InvalidateTokenCache() {
	cachedTokensMu.Lock()
	cachedTokens = nil
	cachedTokensMu.Unlock()
}

// InvalidateProjectCache clears the in-memory cached project config.
func InvalidateProjectCache() {
	cachedProjectConfigMu.Lock()
	cachedProjectConfig = nil
	cachedProjectRoot = ""
	cachedProjectConfigMu.Unlock()
}

// InvalidateWorkspaceKeyCache clears the in-memory cached workspace keys.
func InvalidateWorkspaceKeyCache() {
	cachedWorkspaceKeysMu.Lock()
	cachedWorkspaceKeys = make(map[string][]byte)
	cachedWorkspaceKeysMu.Unlock()
}

// LoadTokens reads user tokens from the secure OS keychain, falling back to ~/.agentsecrets/token.json.
func LoadTokens() (*TokenConfig, error) {
	cachedTokensMu.RLock()
	if cachedTokens != nil {
		t := *cachedTokens
		cachedTokensMu.RUnlock()
		return &t, nil
	}
	cachedTokensMu.RUnlock()

	// 1. Try loading from OS keychain
	tokensJSON, err := keyring.GetUserTokens()
	if err == nil && tokensJSON != "" {
		var tokens TokenConfig
		if err := json.Unmarshal([]byte(tokensJSON), &tokens); err == nil && tokens.AccessToken != "" {
			cachedTokensMu.Lock()
			cachedTokens = &tokens
			cachedTokensMu.Unlock()
			return &tokens, nil
		}
	}

	// 2. Fall back to loading from token.json
	paths, err := GetPaths()
	if err != nil {
		return nil, err
	}
	var tokens TokenConfig
	if err := readJSON(paths.TokenFile, &tokens); err != nil {
		return nil, err
	}

	// 3. Migrate to keyring if tokens were found in file
	if tokens.AccessToken != "" {
		jsonData, err := json.Marshal(&tokens)
		if err == nil {
			_ = keyring.SetUserTokens(string(jsonData))
			// Purge sensitive details from token.json file but preserve file existence
			_ = writeJSON(paths.TokenFile, &TokenConfig{}, 0600)
		}
		cachedTokensMu.Lock()
		cachedTokens = &tokens
		cachedTokensMu.Unlock()
	}

	return &tokens, nil
}

// SaveTokens writes user tokens to the secure OS keychain.
func SaveTokens(tokens *TokenConfig) error {
	cachedTokensMu.Lock()
	if tokens != nil {
		t := *tokens
		cachedTokens = &t
	} else {
		cachedTokens = nil
	}
	cachedTokensMu.Unlock()

	jsonData, err := json.Marshal(tokens)
	if err != nil {
		return fmt.Errorf("failed to serialize tokens: %w", err)
	}

	// Store in secure keychain
	if err := keyring.SetUserTokens(string(jsonData)); err != nil {
		return err
	}

	// Keep token.json file empty of secrets
	paths, err := GetPaths()
	if err != nil {
		return nil
	}
	_ = writeJSON(paths.TokenFile, &TokenConfig{}, 0600)
	return nil
}

// GetProjectRoot walks up the directory tree from the current working directory.
// It returns the absolute or relative path to the nearest directory containing
// '.agentsecrets/project.json'.
// If none is found before reaching the filesystem root, it returns an empty string.
func GetProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		projectFile := filepath.Join(dir, ".agentsecrets", "project.json")
		if _, err := os.Stat(projectFile); err == nil {
			return dir, nil
		}

		parentDir := filepath.Dir(dir)
		// If we've reached the root directory (or if Dir() returns the same dir)
		if parentDir == dir || parentDir == "" || parentDir == string(filepath.Separator) {
			return "", nil
		}
		dir = parentDir
	}
}

// LoadProjectConfig reads .agentsecrets/project.json from the nearest project root.
func LoadProjectConfig() (*ProjectConfig, error) {
	root, err := GetProjectRoot()
	if err != nil {
		return nil, err
	}
	if root == "" {
		return nil, fmt.Errorf("no AgentSecrets project found in this directory or any parent directory.\nRun `agentsecrets init` from your project root to initialise a project")
	}

	cachedProjectConfigMu.RLock()
	if cachedProjectConfig != nil && cachedProjectRoot == root {
		cfg := *cachedProjectConfig
		cachedProjectConfigMu.RUnlock()
		return &cfg, nil
	}
	cachedProjectConfigMu.RUnlock()

	projectFile := filepath.Join(root, ".agentsecrets", "project.json")
	var config ProjectConfig
	if err := readJSON(projectFile, &config); err != nil {
		return nil, err
	}

	cachedProjectConfigMu.Lock()
	cachedProjectConfig = &config
	cachedProjectRoot = root
	cachedProjectConfigMu.Unlock()

	return &config, nil
}

// SaveProjectConfig writes .agentsecrets/project.json to the nearest project root.
func SaveProjectConfig(config *ProjectConfig) error {
	root, err := GetProjectRoot()
	if err != nil {
		return err
	}
	// If root is empty (e.g., initial project creation), write to current directory
	if root == "" {
		root = "."
	}

	cachedProjectConfigMu.Lock()
	if config != nil {
		cfg := *config
		cachedProjectConfig = &cfg
		cachedProjectRoot = root
	} else {
		cachedProjectConfig = nil
	}
	cachedProjectConfigMu.Unlock()

	projectFile := filepath.Join(root, ".agentsecrets", "project.json")
	return writeJSON(projectFile, config, 0644)
}

// --- Helper functions ---

func writeJSON(path string, data interface{}, perm os.FileMode) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(path, jsonData, perm); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

func readJSON(path string, target interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Return zero-value target if file doesn't exist
		}
		return fmt.Errorf("failed to read %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return nil
}

// --- Convenience functions (mirrors Python's CredentialsManager) ---

// GetEmail returns the stored user email, or empty string if not logged in.
func GetEmail() string {
	config, err := LoadGlobalConfig()
	if err != nil {
		return ""
	}
	return config.Email
}

// SetEmail stores the user's email in global config.
func SetEmail(email string) error {
	c, _ := LoadGlobalConfig()
	if c == nil {
		c = &GlobalConfig{}
	}
	c.Email = email
	return SaveGlobalConfig(c)
}

// GetAccessToken returns the current access token, or empty string.
func GetAccessToken() string {
	tokens, err := LoadTokens()
	if err != nil {
		return ""
	}
	return tokens.AccessToken
}

// StoreTokens saves authentication tokens.
func StoreTokens(accessToken, refreshToken, expiresAt string) error {
	return SaveTokens(&TokenConfig{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	})
}

// GetSelectedWorkspaceID returns the selected workspace for new project creation.
func GetSelectedWorkspaceID() string {
	config, err := LoadGlobalConfig()
	if err != nil {
		return ""
	}
	return config.SelectedWorkspaceID
}

// SetSelectedWorkspaceID sets the selected workspace for new project creation.
func SetSelectedWorkspaceID(id string) error {
	c, _ := LoadGlobalConfig()
	if c == nil {
		c = &GlobalConfig{}
	}
	c.SelectedWorkspaceID = id
	return SaveGlobalConfig(c)
}

// GetSelectedProjectID returns the globally selected project ID.
func GetSelectedProjectID() string {
	config, err := LoadGlobalConfig()
	if err != nil {
		return ""
	}
	return config.SelectedProjectID
}

// SetSelectedProjectID sets the globally selected project ID.
func SetSelectedProjectID(id string) error {
	c, _ := LoadGlobalConfig()
	if c == nil {
		c = &GlobalConfig{}
	}
	c.SelectedProjectID = id
	return SaveGlobalConfig(c)
}

// StoreWorkspaceCache saves decrypted workspace keys to the secure OS keychain
// and saves other workspace metadata to the global config with keys stripped out.
func StoreWorkspaceCache(workspaces map[string]WorkspaceCacheEntry) error {
	c, _ := LoadGlobalConfig()
	if c == nil {
		c = &GlobalConfig{}
	}

	// Duplicate the map to avoid modifying the caller's map in-place
	strippedWorkspaces := make(map[string]WorkspaceCacheEntry)

	for id, ws := range workspaces {
		if ws.Key != "" {
			// Save workspace key in secure keychain
			_ = keyring.SetWorkspaceKey(id, ws.Key)
		}
		// Save metadata with Key field stripped
		strippedWorkspaces[id] = WorkspaceCacheEntry{
			Name: ws.Name,
			Key:  "", // Strip the key from config.json
			Role: ws.Role,
			Type: ws.Type,
		}
	}

	c.Workspaces = strippedWorkspaces
	return SaveGlobalConfig(c)
}

// GetWorkspaceKey returns the decrypted workspace key for a given workspace ID.
// It looks up the key in the keyring first. For backward compatibility, if not
// found in the keyring, it falls back to the config.json entry and migrates it.
func GetWorkspaceKey(workspaceID string) ([]byte, error) {
	cachedWorkspaceKeysMu.RLock()
	if key, ok := cachedWorkspaceKeys[workspaceID]; ok && len(key) > 0 {
		cachedWorkspaceKeysMu.RUnlock()
		return key, nil
	}
	cachedWorkspaceKeysMu.RUnlock()

	var keyB64 string

	// 1. Try loading from secure OS keychain
	if k, err := keyring.GetWorkspaceKey(workspaceID); err == nil && k != "" {
		keyB64 = k
	} else {
		// 2. Fall back to loading from config.json
		config, err := LoadGlobalConfig()
		if err != nil {
			return nil, err
		}
		ws, ok := config.Workspaces[workspaceID]
		if !ok || ws.Key == "" {
			return nil, fmt.Errorf("workspace key not found for %s", workspaceID)
		}
		keyB64 = ws.Key

		// 3. Migrate to keyring and strip from config.json
		_ = keyring.SetWorkspaceKey(workspaceID, ws.Key)
		ws.Key = ""
		config.Workspaces[workspaceID] = ws
		_ = SaveGlobalConfig(config)
	}

	// First level of decoding (from base64)
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode workspace key: %w", err)
	}

	// Compatibility: the original Python CLI uses Fernet keys, which are 32-byte keys
	// encoded in base64 (44 chars). When the API sends them asymmetrically encrypted,
	// the "plaintext" inside the box is often the 44-char base64 string rather than the raw 32 bytes.
	if len(key) == 44 {
		// Try standard base64
		if decoded, err := base64.StdEncoding.DecodeString(string(key)); err == nil && len(decoded) == 32 {
			cachedWorkspaceKeysMu.Lock()
			cachedWorkspaceKeys[workspaceID] = decoded
			cachedWorkspaceKeysMu.Unlock()
			return decoded, nil
		}
		// Try URL-safe base64 (Fernet uses this)
		if decoded, err := base64.URLEncoding.DecodeString(string(key)); err == nil && len(decoded) == 32 {
			cachedWorkspaceKeysMu.Lock()
			cachedWorkspaceKeys[workspaceID] = decoded
			cachedWorkspaceKeysMu.Unlock()
			return decoded, nil
		}
	}

	cachedWorkspaceKeysMu.Lock()
	cachedWorkspaceKeys[workspaceID] = key
	cachedWorkspaceKeysMu.Unlock()

	return key, nil
}

// GetProjectWorkspaceKey returns the workspace key for the current project directory.
func GetProjectWorkspaceKey() ([]byte, error) {
	p, err := LoadProjectConfig()
	if err != nil || p.WorkspaceID == "" {
		return nil, fmt.Errorf("no project configured in current directory")
	}
	return GetWorkspaceKey(p.WorkspaceID)
}

// GetSelectedWorkspaceKey returns the workspace key for the currently active/selected workspace.
func GetSelectedWorkspaceKey() ([]byte, error) {
	wsID := GetSelectedWorkspaceID()
	if wsID == "" {
		return nil, fmt.Errorf("no workspace selected")
	}
	return GetWorkspaceKey(wsID)
}

// IsAuthenticated checks if the user has a valid session (token + email present).
func IsAuthenticated() bool {
	return GetAccessToken() != "" && GetEmail() != ""
}

// ClearSession removes all stored credentials (logout).
// Does NOT clear project.json.
func ClearSession() error {
	cachedTokensMu.Lock()
	cachedTokens = nil
	cachedTokensMu.Unlock()

	cachedWorkspaceKeysMu.Lock()
	cachedWorkspaceKeys = make(map[string][]byte)
	cachedWorkspaceKeysMu.Unlock()

	// 1. Purge keychain credentials
	_ = keyring.DeleteUserTokens()

	config, err := LoadGlobalConfig()
	if err == nil && config != nil {
		for id := range config.Workspaces {
			_ = keyring.DeleteWorkspaceKey(id)
		}
	}

	// 2. Clear config files on disk
	paths, err := GetPaths()
	if err != nil {
		return err
	}

	// Reset config to empty (preserves the file)
	if err := writeJSON(paths.ConfigFile, &GlobalConfig{}, 0600); err != nil {
		return err
	}

	// Reset tokens to empty
	if err := writeJSON(paths.TokenFile, &TokenConfig{}, 0600); err != nil {
		return err
	}

	return nil
}

// ClearProjectConfig resets the local .agentsecrets/project.json file.
func ClearProjectConfig() error {
	cachedProjectConfigMu.Lock()
	cachedProjectConfig = nil
	cachedProjectRoot = ""
	cachedProjectConfigMu.Unlock()

	root, _ := GetProjectRoot()
	if root == "" {
		return nil // nothing to clear
	}

	projectFile := filepath.Join(root, ".agentsecrets", "project.json")

	// Check if it exists first
	if _, err := os.Stat(projectFile); os.IsNotExist(err) {
		return nil
	}

	defaultConfig := &ProjectConfig{Environment: "development"}
	return writeJSON(projectFile, defaultConfig, 0644)
}

// GetStorageMode returns the configured storage mode (1: keychain, 2: env_file).
// Resolution order:
// 1. AGENTSECRETS_STORAGE_MODE environment variable
// 2. .agentsecrets/project.json storage_mode
// 3. ~/.agentsecrets/config.json default_storage_mode
// 4. Default to 1 (keychain)
func GetStorageMode() int {
	// 1. Env var
	if env := os.Getenv("AGENTSECRETS_STORAGE_MODE"); env != "" {
		if env == "2" {
			return 2
		}
		return 1
	}

	// 2. Project config
	if pc, err := LoadProjectConfig(); err == nil && pc.StorageMode != 0 {
		return pc.StorageMode
	}

	// 3. Global config
	if gc, err := LoadGlobalConfig(); err == nil && gc.DefaultStorageMode != 0 {
		return gc.DefaultStorageMode
	}

	return 1 // Default to keychain
}

// SetStorageMode updates the default storage mode in the global config.
func SetStorageMode(mode int) error {
	c, err := LoadGlobalConfig()
	if err != nil || c == nil {
		c = &GlobalConfig{}
	}
	c.DefaultStorageMode = mode
	return SaveGlobalConfig(c)
}

// --- Environment Resolution ---

// ValidEnvironments is the list of valid environment names.
var ValidEnvironments = []string{"development", "staging", "production"}

// IsValidEnvironment returns true if the given string is a valid environment name.
func IsValidEnvironment(env string) bool {
	for _, valid := range ValidEnvironments {
		if env == valid {
			return true
		}
	}
	return false
}

// ResolveEnvironment returns the active environment for the current context.
// Resolution order:
// 1. AGENTSECRETS_ENV environment variable
// 2. .agentsecrets/project.json environment field (walk up from cwd)
// 3. ~/.agentsecrets/config.json selected_environment
// 4. "development" (hardcoded default)
func ResolveEnvironment() string {
	env, _ := ResolveEnvironmentWithSource()
	return env
}

// ResolveEnvironmentWithSource returns the active environment and its source.
// Sources: "AGENTSECRETS_ENV", "project.json", "global config", "default"
func ResolveEnvironmentWithSource() (string, string) {
	// 1. Check env var
	if env := os.Getenv("AGENTSECRETS_ENV"); env != "" {
		if !IsValidEnvironment(env) {
			fmt.Fprintf(os.Stderr, "Warning: AGENTSECRETS_ENV=%s is not a valid environment. Using development.\nValid environments: development, staging, production\n", env)
			return "development", "default"
		}
		return env, "AGENTSECRETS_ENV"
	}

	// 2. Check project.json (use existing project root walk-up logic)
	if p, err := LoadProjectConfig(); err == nil && p != nil {
		if p.Environment != "" && IsValidEnvironment(p.Environment) {
			return p.Environment, "project.json"
		}
	}

	// 3. Check global config
	if c, err := LoadGlobalConfig(); err == nil && c != nil {
		if c.SelectedEnvironment != "" && IsValidEnvironment(c.SelectedEnvironment) {
			return c.SelectedEnvironment, "global config"
		}
	}

	// 4. Default
	return "development", "default"
}

// SetSelectedEnvironment sets the globally selected environment.
func SetSelectedEnvironment(env string) error {
	c, _ := LoadGlobalConfig()
	if c == nil {
		c = &GlobalConfig{}
	}
	c.SelectedEnvironment = env
	return SaveGlobalConfig(c)
}

// parseExpiresAt parses an ISO 8601 / RFC 3339 timestamp, handling both
// standard (no fractional seconds) and Python-style (microsecond-precision)
// formats. Python's datetime.isoformat() produces timestamps like
// "2026-06-11T06:29:32.123456+00:00" which time.RFC3339 rejects.
func parseExpiresAt(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339Nano, s)
}

// IsTokenExpired returns true if the current access token is expired or close to expiring (within 5 minutes).
func IsTokenExpired() bool {
	tokens, err := LoadTokens()
	if err != nil || tokens == nil || tokens.AccessToken == "" {
		return true
	}
	if tokens.ExpiresAt == "" {
		return false
	}
	exp, err := parseExpiresAt(tokens.ExpiresAt)
	if err != nil {
		return true
	}
	return time.Until(exp) < 5*time.Minute
}
