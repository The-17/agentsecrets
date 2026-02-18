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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// GlobalConfig represents ~/.agentsecrets/config.json
type GlobalConfig struct {
	Email               string                      `json:"email,omitempty"`
	SelectedWorkspaceID string                      `json:"selected_workspace_id,omitempty"`
	Workspaces          map[string]WorkspaceCacheEntry `json:"workspaces,omitempty"`
}

// WorkspaceCacheEntry is a cached workspace with its decrypted key
type WorkspaceCacheEntry struct {
	Name string `json:"name"`
	Key  string `json:"key"`  // Base64-encoded decrypted workspace key
	Role string `json:"role"` // "owner", "admin", "member"
	Type string `json:"type"` // "personal", "team"
}

// TokenConfig represents ~/.agentsecrets/token.json
type TokenConfig struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
}

// ProjectConfig represents ./.agentsecrets/project.json
type ProjectConfig struct {
	ProjectID     string `json:"project_id,omitempty"`
	ProjectName   string `json:"project_name,omitempty"`
	Description   string `json:"description,omitempty"`
	Environment   string `json:"environment,omitempty"` // "development", "staging", "production"
	WorkspaceID   string `json:"workspace_id,omitempty"`
	WorkspaceName string `json:"workspace_name,omitempty"`
	LastPull      string `json:"last_pull,omitempty"`
	LastPush      string `json:"last_push,omitempty"`
}

// Paths returns the standard config file paths
type Paths struct {
	GlobalDir  string // ~/.agentsecrets/
	ConfigFile string // ~/.agentsecrets/config.json
	TokenFile  string // ~/.agentsecrets/token.json
}

// GetPaths returns the standard config paths based on the user's home directory.
func GetPaths() (*Paths, error) {
	home, err := os.UserHomeDir()
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
		if err := writeJSON(paths.ConfigFile, &GlobalConfig{}, 0644); err != nil {
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
func InitProjectConfig() error {
	projectDir := filepath.Join(".", ".agentsecrets")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		return fmt.Errorf("failed to create project config directory: %w", err)
	}

	projectFile := filepath.Join(projectDir, "project.json")
	if _, err := os.Stat(projectFile); os.IsNotExist(err) {
		defaultConfig := &ProjectConfig{Environment: "development"}
		if err := writeJSON(projectFile, defaultConfig, 0644); err != nil {
			return err
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
	var config GlobalConfig
	if err := readJSON(paths.ConfigFile, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// SaveGlobalConfig writes ~/.agentsecrets/config.json
func SaveGlobalConfig(config *GlobalConfig) error {
	paths, err := GetPaths()
	if err != nil {
		return err
	}
	return writeJSON(paths.ConfigFile, config, 0644)
}

// LoadTokens reads ~/.agentsecrets/token.json
func LoadTokens() (*TokenConfig, error) {
	paths, err := GetPaths()
	if err != nil {
		return nil, err
	}
	var tokens TokenConfig
	if err := readJSON(paths.TokenFile, &tokens); err != nil {
		return nil, err
	}
	return &tokens, nil
}

// SaveTokens writes ~/.agentsecrets/token.json
func SaveTokens(tokens *TokenConfig) error {
	paths, err := GetPaths()
	if err != nil {
		return err
	}
	return writeJSON(paths.TokenFile, tokens, 0600)
}

// LoadProjectConfig reads .agentsecrets/project.json from the current directory.
func LoadProjectConfig() (*ProjectConfig, error) {
	projectFile := filepath.Join(".", ".agentsecrets", "project.json")
	var config ProjectConfig
	if err := readJSON(projectFile, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// SaveProjectConfig writes .agentsecrets/project.json in the current directory.
func SaveProjectConfig(config *ProjectConfig) error {
	projectFile := filepath.Join(".", ".agentsecrets", "project.json")
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
		return fmt.Errorf("failed to read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return nil
}
