//go:build !linux && !windows && !darwin

package commands

import (
	"fmt"
	"os"
	"syscall"
)

// hardenParentProcess is a no-op off Linux; the equivalent parent-protection
// primitives are added per-platform in a later phase.
func hardenParentProcess() {}

// childSysProcAttr detaches the child from the controlling terminal where the
// platform supports it.
func childSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// isTerminal reports whether f is attached to a terminal.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// sandboxArgv is not available on this platform yet.
func sandboxArgv(args []string) ([]string, error) {
	return nil, fmt.Errorf("--sandbox is currently supported on Linux only")
}

// guardAttachWarning has nothing to report: no preload guard is wired up for this
// platform, so there is no attachment to warn about.
func guardAttachWarning(target string) string { return "" }
