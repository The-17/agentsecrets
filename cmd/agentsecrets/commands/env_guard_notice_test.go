package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/The-17/agentsecrets/pkg/config"
)

func TestGuardNoticeOnce(t *testing.T) {
	dir := t.TempDir()
	orig := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return dir, nil }
	t.Cleanup(func() { config.HomeDirHook = orig })

	if !guardNoticePending() {
		t.Fatal("the first check should show the notice")
	}
	markGuardNoticeSeen()
	if guardNoticePending() {
		t.Fatal("the notice must not repeat on every env run")
	}
	if _, err := os.Stat(filepath.Join(dir, ".agentsecrets", envGuardNoticeFile)); err != nil {
		t.Fatalf("expected the one-time marker, got %v", err)
	}
}
