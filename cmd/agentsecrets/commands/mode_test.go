package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
)

// useModeProject pins project resolution to a temporary project and redirects
// the global config to a temp home, so `mode --project` writes only there.
func useModeProject(t *testing.T) (projectDir string) {
	t.Helper()
	home := t.TempDir()
	oldHome := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return home, nil }
	t.Cleanup(func() { config.HomeDirHook = oldHome })

	projectDir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, ".agentsecrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, ".agentsecrets", "project.json"), []byte(`{"project_id":"p-1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.ProjectDirEnv, projectDir)
	config.InvalidateProjectCache()
	t.Cleanup(config.InvalidateProjectCache)
	return projectDir
}

func modeTestCommand() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().Bool("project", false, "")
	return cmd
}

func TestRunModeProjectScope(t *testing.T) {
	useModeProject(t)

	cmd := modeTestCommand()
	if err := cmd.Flags().Set("project", "true"); err != nil {
		t.Fatal(err)
	}
	if err := runMode(cmd, []string{"cloud"}); err != nil {
		t.Fatalf("runMode(cloud --project): %v", err)
	}
	if got := config.GetProjectMode(); got != "cloud" {
		t.Errorf("project mode = %q, want cloud", got)
	}
	if got := config.GetDefaultMode(); got != "" {
		t.Errorf("global mode = %q, want unset: --project must not write it", got)
	}
}

func TestRunModeGlobalScopeDoesNotWriteProject(t *testing.T) {
	projectDir := useModeProject(t)

	cmd := modeTestCommand()
	if err := runMode(cmd, []string{"cloud"}); err != nil {
		t.Fatalf("runMode(cloud): %v", err)
	}
	if got := config.GetDefaultMode(); got != "cloud" {
		t.Errorf("global mode = %q, want cloud", got)
	}
	data, err := os.ReadFile(filepath.Join(projectDir, ".agentsecrets", "project.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := config.GetProjectMode(); got != "" {
		t.Errorf("project mode = %q, want unset: global scope must not write it", got)
	}
	if string(data) != `{"project_id":"p-1"}` {
		t.Errorf("project.json was rewritten by a global mode change: %s", data)
	}
}

func TestRunModeRejectsUnknownMode(t *testing.T) {
	useModeProject(t)
	if err := runMode(modeTestCommand(), []string{"hybrid"}); err == nil {
		t.Fatal("expected an error for an unknown mode")
	}
}
