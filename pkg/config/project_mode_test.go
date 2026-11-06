package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// withProjectDir pins project resolution to a temporary project for the test
// and resets the shared override and cache afterwards. Mode reads must be
// deterministic: a developer's own .agentsecrets/project.json must not decide
// the outcome of a package test.
func withProjectDir(t *testing.T, projectJSON string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".agentsecrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".agentsecrets", "project.json"), []byte(projectJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	projectDirOverrideMu.Lock()
	projectDirOverride = dir
	projectDirOverrideMu.Unlock()
	InvalidateProjectCache()
	t.Cleanup(func() {
		projectDirOverrideMu.Lock()
		projectDirOverride = ""
		projectDirOverrideMu.Unlock()
		InvalidateProjectCache()
	})
	return dir
}

func TestProjectModeRoundtrip(t *testing.T) {
	dir := withProjectDir(t, `{"project_id":"p-1","workspace_id":"ws-1"}`)

	if got := GetProjectMode(); got != "" {
		t.Fatalf("unset project mode = %q, want empty", got)
	}

	if err := SetProjectMode("cloud"); err != nil {
		t.Fatalf("SetProjectMode(cloud): %v", err)
	}
	if got := GetProjectMode(); got != "cloud" {
		t.Errorf("project mode = %q, want cloud", got)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".agentsecrets", "project.json"))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk ProjectConfig
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("project.json is not valid JSON: %v", err)
	}
	if onDisk.Mode != "cloud" {
		t.Errorf("mode was not persisted to project.json: got %q", onDisk.Mode)
	}

	if err := SetProjectMode("local"); err != nil {
		t.Fatalf("SetProjectMode(local): %v", err)
	}
	if got := GetProjectMode(); got != "local" {
		t.Errorf("project mode = %q, want local", got)
	}

	if err := SetProjectMode("hybrid"); err == nil {
		t.Fatal("expected an error for an unknown project mode")
	}
	if got := GetProjectMode(); got != "local" {
		t.Errorf("rejected mode changed stored value to %q", got)
	}
}

func TestProjectModeCorruptValueIgnored(t *testing.T) {
	withProjectDir(t, `{"project_id":"p-1","mode":"hybrid"}`)
	if got := GetProjectMode(); got != "" {
		t.Errorf("corrupt project mode = %q, want empty", got)
	}
}

func TestProjectModeNoProjectFailsLoudly(t *testing.T) {
	// An env var pointing at a directory with no project marker makes
	// GetProjectRoot fail. GetProjectMode absorbs that (no project means no
	// choice), but SetProjectMode must refuse rather than create a stray file.
	empty := t.TempDir()
	t.Setenv(ProjectDirEnv, empty)
	projectDirOverrideMu.Lock()
	projectDirOverride = ""
	projectDirOverrideMu.Unlock()
	InvalidateProjectCache()
	t.Cleanup(InvalidateProjectCache)

	if got := GetProjectMode(); got != "" {
		t.Errorf("project mode outside a project = %q, want empty", got)
	}
	if err := SetProjectMode("cloud"); err == nil {
		t.Fatal("expected SetProjectMode to fail outside a project")
	}
	if _, err := os.Stat(filepath.Join(empty, ".agentsecrets", "project.json")); !os.IsNotExist(err) {
		t.Errorf("a stray project.json was created outside a project: %v", err)
	}
}

func TestProjectModeDoesNotTouchGlobalMode(t *testing.T) {
	tmp := t.TempDir()
	oldHome := HomeDirHook
	HomeDirHook = func() (string, error) { return tmp, nil }
	t.Cleanup(func() { HomeDirHook = oldHome })

	withProjectDir(t, `{"project_id":"p-1"}`)
	if err := SetDefaultMode("local"); err != nil {
		t.Fatal(err)
	}
	if err := SetProjectMode("cloud"); err != nil {
		t.Fatal(err)
	}
	if got := GetDefaultMode(); got != "local" {
		t.Errorf("global mode = %q, want local: project mode must not rewrite it", got)
	}
	if got := GetProjectMode(); got != "cloud" {
		t.Errorf("project mode = %q, want cloud", got)
	}
}

// A failed save must not leave the in-memory config claiming a mode that never
// reached disk. Select routes on this value, so a stale cache entry would put
// the process on the billed cloud path without a persisted choice behind it.
func TestProjectModeFailedSaveDoesNotLeakIntoCache(t *testing.T) {
	dir := withProjectDir(t, `{"project_id":"p-1"}`)
	projectFile := filepath.Join(dir, ".agentsecrets", "project.json")

	// Replace the config file with a directory so the write is certain to fail
	// regardless of file mode or owner. Running as root, a chmod-only harness
	// silently succeeds and proves nothing.
	if err := os.Remove(projectFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(projectFile, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(projectFile) })

	if err := SetProjectMode("cloud"); err == nil {
		t.Fatal("expected SetProjectMode to fail when project.json cannot be written")
	}
	if got := GetProjectMode(); got != "" {
		t.Errorf("project mode = %q, want empty: a failed save must not enter the cache", got)
	}
}

// SetProjectMode must not alias the cached config. Mutating the struct it hands
// back would corrupt the cache for every later reader.
func TestSetProjectModeDoesNotAliasTheCache(t *testing.T) {
	withProjectDir(t, `{"project_id":"p-1"}`)
	pc, err := LoadProjectConfig()
	if err != nil {
		t.Fatal(err)
	}
	pc.Mode = "cloud"

	if got := GetProjectMode(); got != "" {
		t.Errorf("project mode = %q, want empty: the caller's edit leaked into the cache", got)
	}

	if err := SetProjectMode("local"); err != nil {
		t.Fatal(err)
	}
	if got := GetProjectMode(); got != "local" {
		t.Errorf("project mode = %q, want local", got)
	}
}
