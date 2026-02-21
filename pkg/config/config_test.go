package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigRoundtrip(t *testing.T) {
	// Setup: redirect home directory to a temp one
	tmpDir := t.TempDir()
	oldHome := HomeDirHook
	HomeDirHook = func() (string, error) { return tmpDir, nil }
	defer func() { HomeDirHook = oldHome }()

	// 1. Init
	if err := InitGlobalConfig(); err != nil {
		t.Fatalf("InitGlobalConfig failed: %v", err)
	}

	// Verify directory and files created
	paths, _ := GetPaths()
	if _, err := os.Stat(paths.GlobalDir); os.IsNotExist(err) {
		t.Error("Global config directory was not created")
	}
	if _, err := os.Stat(paths.ConfigFile); os.IsNotExist(err) {
		t.Error("config.json was not created")
	}
	if _, err := os.Stat(paths.TokenFile); os.IsNotExist(err) {
		t.Error("token.json was not created")
	}

	// 2. Save and Load Global Config
	cfg := &GlobalConfig{
		Email:               "test@example.com",
		SelectedWorkspaceID: "ws-123",
		Workspaces: map[string]WorkspaceCacheEntry{
			"ws-123": {Name: "Test WS", Key: "base64key", Type: "shared"},
		},
	}
	if err := SaveGlobalConfig(cfg); err != nil {
		t.Fatalf("SaveGlobalConfig failed: %v", err)
	}

	loaded, err := LoadGlobalConfig()
	if err != nil {
		t.Fatalf("LoadGlobalConfig failed: %v", err)
	}
	if loaded.Email != cfg.Email || loaded.SelectedWorkspaceID != cfg.SelectedWorkspaceID {
		t.Error("Loaded config does not match saved config")
	}
	if loaded.Workspaces["ws-123"].Name != "Test WS" {
		t.Error("Nested workspace cache entry missing or incorrect")
	}

	// 3. Tokens
	tokens := &TokenConfig{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
		ExpiresAt:    "2025-01-01T00:00:00Z",
	}
	if err := SaveTokens(tokens); err != nil {
		t.Fatalf("SaveTokens failed: %v", err)
	}

	loadedTokens, err := LoadTokens()
	if err != nil {
		t.Fatalf("LoadTokens failed: %v", err)
	}
	if loadedTokens.AccessToken != tokens.AccessToken {
		t.Error("Loaded tokens do not match saved tokens")
	}

	// 4. Convenience getters
	if GetEmail() != "test@example.com" {
		t.Errorf("GetEmail returned %q, expected %q", GetEmail(), "test@example.com")
	}
	if GetAccessToken() != "access-123" {
		t.Errorf("GetAccessToken returned %q, expected %q", GetAccessToken(), "access-123")
	}
	if !IsAuthenticated() {
		t.Error("IsAuthenticated returned false, expected true")
	}

	// 5. Clear Session
	if err := ClearSession(); err != nil {
		t.Fatalf("ClearSession failed: %v", err)
	}
	if GetEmail() != "" || GetAccessToken() != "" || IsAuthenticated() {
		t.Error("ClearSession did not fully purge credentials")
	}
}

func TestProjectConfig(t *testing.T) {
	// Setup: run in a temp directory for project config
	tmpDir := t.TempDir()
	originalWD, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change working directory: %v", err)
	}
	defer os.Chdir(originalWD)

	if err := InitProjectConfig(); err != nil {
		t.Fatalf("InitProjectConfig failed: %v", err)
	}

	projectFile := filepath.Join(".agentsecrets", "project.json")
	if _, err := os.Stat(projectFile); os.IsNotExist(err) {
		t.Error("project.json was not created")
	}

	cfg := &ProjectConfig{
		ProjectID:   "p-123",
		ProjectName: "Test Project",
		WorkspaceID: "ws-999",
	}
	if err := SaveProjectConfig(cfg); err != nil {
		t.Fatalf("SaveProjectConfig failed: %v", err)
	}

	loaded, err := LoadProjectConfig()
	if err != nil {
		t.Fatalf("LoadProjectConfig failed: %v", err)
	}
	if loaded.ProjectID != "p-123" || loaded.WorkspaceID != "ws-999" {
		t.Error("Loaded project config does not match saved")
	}
}
