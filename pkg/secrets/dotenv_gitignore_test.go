package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureEnvGitignore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	if err := os.WriteFile(path, []byte("node_modules\n.env\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := EnsureEnvGitignore(dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"node_modules", ".env", ".env.staging", ".env.production"} {
		if !strings.Contains(string(first), want) {
			t.Errorf("missing %q in gitignore:\n%s", want, first)
		}
	}

	if err := EnsureEnvGitignore(dir); err != nil {
		t.Fatalf("second call: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Errorf("operation must be idempotent, first:\n%s\nsecond:\n%s", first, second)
	}
}
