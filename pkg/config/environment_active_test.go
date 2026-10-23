package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCustomEnvironmentBecomesActiveContext proves `environment switch qa` makes
// qa the environment every later command resolves, including the keychain, which
// keys entries by the resolved name with no allowlist of its own.
func TestCustomEnvironmentBecomesActiveContext(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)

	// A project bound to qa the way `environment switch qa` writes it.
	projectDir := filepath.Join(root, ".agentsecrets")
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfg := &ProjectConfig{
		ProjectID:   "prj-1",
		ProjectName: "checkout-api",
		WorkspaceID: "ws-1",
		Environment: "qa",
	}
	if err := SaveProjectConfig(cfg); err != nil {
		t.Fatalf("SaveProjectConfig: %v", err)
	}

	env, source := ResolveEnvironmentWithSource()
	if env != "qa" {
		t.Fatalf("ResolveEnvironment = %q, want qa", env)
	}
	if source != "project.json" {
		t.Fatalf("source = %q, want project.json", source)
	}
}

// TestCustomEnvironmentFromEnvVar proves AGENTSECRETS_ENV=q a custom name is
// honoured too, so a shell session can pin one without touching config.
func TestCustomEnvironmentFromEnvVar(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AGENTSECRETS_ENV", "preview-pr-12")

	env, source := ResolveEnvironmentWithSource()
	if env != "preview-pr-12" {
		t.Fatalf("ResolveEnvironment = %q, want preview-pr-12", env)
	}
	if source != "AGENTSECRETS_ENV" {
		t.Fatalf("source = %q, want AGENTSECRETS_ENV", source)
	}
}

// TestInvalidEnvVarFallsBackLoudly proves a malformed AGENTSECRETS_ENV degrades to
// development rather than being used verbatim as a keychain target.
func TestInvalidEnvVarFallsBackLoudly(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AGENTSECRETS_ENV", "has space")

	env, source := ResolveEnvironmentWithSource()
	if env != "development" || source != "default" {
		t.Fatalf("ResolveEnvironment = (%q, %q), want (development, default)", env, source)
	}
}
