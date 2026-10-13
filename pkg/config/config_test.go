package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/The-17/agentsecrets/pkg/keychainauth"
	"github.com/The-17/agentsecrets/pkg/keyring"
)

func TestConfigRoundtrip(t *testing.T) {
	// Setup: redirect home directory to a temp one
	tmpDir := t.TempDir()
	oldHome := HomeDirHook
	HomeDirHook = func() (string, error) { return tmpDir, nil }
	defer func() { HomeDirHook = oldHome }()

	// Set up the in-memory test stub for keychain-auth
	keychainauth.SetupTestStub()
	defer keychainauth.TeardownTestStub()

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

	// 2. Save and Load Global Config (Workspace Cache Keychain delegation)
	cfg := &GlobalConfig{
		Email:               "test@example.com",
		SelectedWorkspaceID: "ws-123",
	}
	if err := SaveGlobalConfig(cfg); err != nil {
		t.Fatalf("SaveGlobalConfig failed: %v", err)
	}

	testWorkspaceKey := "bXktc2VjcmV0LWtleS0zMi1jaGFycy1sb25nLWhlcmUt" // valid base64 key
	workspaces := map[string]WorkspaceCacheEntry{
		"ws-123": {Name: "Test WS", Key: testWorkspaceKey, Type: "shared"},
	}

	if err := StoreWorkspaceCache(workspaces); err != nil {
		t.Fatalf("StoreWorkspaceCache failed: %v", err)
	}

	// Verify that config.json on disk does NOT contain the key
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
	if loaded.Workspaces["ws-123"].Key != "" {
		t.Error("Workspace key was saved to config.json! It should have been stripped and saved to keyring.")
	}

	// Verify we can retrieve it via GetWorkspaceKey
	retrievedKey, err := GetWorkspaceKey("ws-123")
	if err != nil {
		t.Fatalf("GetWorkspaceKey failed: %v", err)
	}
	if string(retrievedKey) != "my-secret-key-32-chars-long-here-" {
		t.Errorf("GetWorkspaceKey returned incorrect value: %q", string(retrievedKey))
	}

	// 3. Tokens Secure storage
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

	// Verify that token.json file on disk is empty of secrets
	diskTokens := &TokenConfig{}
	if err := readJSON(paths.TokenFile, diskTokens); err != nil {
		t.Fatalf("readJSON token.json failed: %v", err)
	}
	if diskTokens.AccessToken != "" || diskTokens.RefreshToken != "" {
		t.Error("Tokens were written in plaintext to token.json!")
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

	// 4.5. Test migration behavior
	// Manually write tokens to token.json
	legacyTokens := &TokenConfig{
		AccessToken:  "legacy-access",
		RefreshToken: "legacy-refresh",
	}
	InvalidateTokenCache()
	_ = keyring.DeleteUserTokens() // Clear from keyring first
	if err := writeJSON(paths.TokenFile, legacyTokens, 0600); err != nil {
		t.Fatalf("Failed to write legacy token.json: %v", err)
	}

	// LoadTokens should detect it, migrate it, and clear the file
	migratedTokens, err := LoadTokens()
	if err != nil {
		t.Fatalf("LoadTokens migration failed: %v", err)
	}
	if migratedTokens.AccessToken != "legacy-access" {
		t.Errorf("Failed to read legacy token: %s", migratedTokens.AccessToken)
	}
	// Verify it's in keyring now
	keyringJSON, err := keyring.GetUserTokens()
	if err != nil || keyringJSON == "" {
		t.Error("Tokens were not migrated to keyring")
	}
	// Verify file is cleared
	diskTokens2 := &TokenConfig{}
	_ = readJSON(paths.TokenFile, diskTokens2)
	if diskTokens2.AccessToken != "" {
		t.Error("token.json was not cleared after migration")
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

	if err := InitProjectConfig(1); err != nil {
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

func TestProjectDirOverride(t *testing.T) {
	// Fixture project, resolved from a directory that has no project.
	projDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projDir, ".agentsecrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(projDir, ".agentsecrets", "project.json")
	if err := os.WriteFile(marker, []byte(`{"project_id":"p-override","workspace_id":"ws-1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	emptyDir := t.TempDir()
	t.Chdir(emptyDir)
	t.Setenv(ProjectDirEnv, "")

	projectDirOverrideMu.Lock()
	projectDirOverride = ""
	projectDirOverrideMu.Unlock()
	t.Cleanup(func() {
		projectDirOverrideMu.Lock()
		projectDirOverride = ""
		projectDirOverrideMu.Unlock()
		os.Unsetenv(ProjectDirEnv)
	})

	// 1. No override, empty cwd: not found (root "", nil error by contract).
	if root, _ := GetProjectRoot(); root != "" {
		t.Errorf("expected empty root from empty cwd, got %q", root)
	}
	// 2. Env var pins the fixture.
	t.Setenv(ProjectDirEnv, projDir)
	root, err := GetProjectRoot()
	if err != nil || root != projDir {
		t.Fatalf("env override: root=%q err=%v", root, err)
	}
	// 3. Explicit flag override beats env (point it nowhere-valid would fail,
	// so point it at the fixture too and confirm precedence by value).
	os.Unsetenv(ProjectDirEnv)
	if err := SetProjectDirOverride(projDir); err != nil {
		t.Fatalf("SetProjectDirOverride: %v", err)
	}
	t.Setenv(ProjectDirEnv, emptyDir)
	root, err = GetProjectRoot()
	if err != nil || root != projDir {
		t.Fatalf("flag override must beat env: root=%q err=%v", root, err)
	}
	// 4. Invalid dirs fail fast, never silently.
	if err := SetProjectDirOverride(emptyDir); err == nil {
		t.Error("expected error for non-project dir")
	}
	os.Unsetenv(ProjectDirEnv)
	projectDirOverrideMu.Lock()
	projectDirOverride = ""
	projectDirOverrideMu.Unlock()
	if root, _ := GetProjectRoot(); root != "" {
		t.Errorf("expected empty root after clearing override in empty cwd, got %q", root)
	}
}
