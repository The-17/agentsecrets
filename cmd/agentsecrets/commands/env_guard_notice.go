package commands

import (
	"os"
	"path/filepath"

	"github.com/The-17/agentsecrets/pkg/config"
)

const envGuardNoticeFile = ".envguard-notice"

// guardNoticeOnce reports whether the missing-guard notice has not been shown
// before. The old warning printed a `make envguard` instruction on every env
// run. Package users have no makefile, and a protection notice repeated on
// every invocation trains them to ignore it. Show it once, in plain language.
func guardNoticeOnce() bool {
	paths, err := config.GetPaths()
	if err != nil {
		return false
	}
	marker := filepath.Join(paths.GlobalDir, envGuardNoticeFile)
	if _, err := os.Stat(marker); err == nil {
		return false
	}
	if err := os.MkdirAll(paths.GlobalDir, 0700); err != nil {
		return false
	}
	if err := os.WriteFile(marker, []byte("1\n"), 0600); err != nil {
		return false
	}
	return true
}
