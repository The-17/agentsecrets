package commands

import (
	"os"
	"path/filepath"

	"github.com/The-17/agentsecrets/pkg/config"
)

const envGuardNoticeFile = ".envguard-notice"

// guardNoticePending reports whether the missing-guard notice has not been
// shown before. It does not write the marker: the caller writes it only after
// the notice has actually been printed.
func guardNoticePending() bool {
	paths, err := config.GetPaths()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(paths.GlobalDir, envGuardNoticeFile))
	return err != nil
}

// markGuardNoticeSeen records that the notice was shown on this machine.
func markGuardNoticeSeen() {
	paths, err := config.GetPaths()
	if err != nil {
		return
	}
	if err := os.MkdirAll(paths.GlobalDir, 0700); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(paths.GlobalDir, envGuardNoticeFile), []byte("1\n"), 0600)
}
