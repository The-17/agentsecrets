package config

import (
	"os"
	"path/filepath"
	"testing"
)

// tempHome saves a GlobalConfig with a personal + shared workspace into a temp
// home dir so ResolveWorkspaceRef / env overrides have real data to read.
func tempHomeWithConfig(t *testing.T, cfg *GlobalConfig) {
	t.Helper()
	orig := HomeDirHook
	tmp := t.TempDir()
	globalDir := filepath.Join(tmp, ".agentsecrets")
	if err := os.MkdirAll(globalDir, 0o700); err != nil {
		t.Fatalf("mkdir global dir: %v", err)
	}
	HomeDirHook = func() (string, error) { return tmp, nil }
	t.Cleanup(func() { HomeDirHook = orig })
	if err := SaveGlobalConfig(cfg); err != nil {
		t.Fatalf("save global config: %v", err)
	}
}

func sampleConfig() *GlobalConfig {
	return &GlobalConfig{
		Email:               "test@example.com",
		SelectedWorkspaceID: "ws-org",
		SelectedProjectID:   "proj-default",
		Workspaces: map[string]WorkspaceCacheEntry{
			"ws-personal": {Name: "go", Type: "personal"},
			"ws-org":      {Name: "acme", Type: "shared"},
		},
	}
}

func TestResolveWorkspaceRef(t *testing.T) {
	tempHomeWithConfig(t, sampleConfig())

	cases := []struct {
		ref      string
		wantID   string
		wantErr  bool
	}{
		{"personal", "ws-personal", false}, // portable per-call address
		{"acme", "ws-org", false},          // by display name
		{"ws-org", "ws-org", false},        // by id
		{"ghost", "", true},                // unknown fails closed
	}
	for _, c := range cases {
		got, err := ResolveWorkspaceRef(c.ref)
		if c.wantErr {
			if err == nil {
				t.Errorf("ResolveWorkspaceRef(%q): want error, got id %q", c.ref, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ResolveWorkspaceRef(%q): unexpected error: %v", c.ref, err)
			continue
		}
		if got != c.wantID {
			t.Errorf("ResolveWorkspaceRef(%q) = %q, want %q", c.ref, got, c.wantID)
		}
	}
}

// AGENTSECRETS_WORKSPACE is the stateless per-process scoped handle for
// workspace_switch: it must override the shared selection without mutating it.
func TestSelectedWorkspaceEnvOverride(t *testing.T) {
	tempHomeWithConfig(t, sampleConfig())

	// No override → persisted selection wins.
	if got := GetSelectedWorkspaceID(); got != "ws-org" {
		t.Errorf("GetSelectedWorkspaceID() = %q, want ws-org", got)
	}

	t.Setenv("AGENTSECRETS_WORKSPACE", "personal")
	if got := GetSelectedWorkspaceID(); got != "ws-personal" {
		t.Errorf("AGENTSECRETS_WORKSPACE=personal → GetSelectedWorkspaceID() = %q, want ws-personal", got)
	}
}

// AGENTSECRETS_PROJECT is the per-process override counterpart for projects.
func TestSelectedProjectEnvOverride(t *testing.T) {
	tempHomeWithConfig(t, sampleConfig())

	if got := GetSelectedProjectID(); got != "proj-default" {
		t.Errorf("GetSelectedProjectID() = %q, want proj-default", got)
	}

	t.Setenv("AGENTSECRETS_PROJECT", "proj-x")
	if got := GetSelectedProjectID(); got != "proj-x" {
		t.Errorf("AGENTSECRETS_PROJECT=proj-x → GetSelectedProjectID() = %q, want proj-x", got)
	}
}
