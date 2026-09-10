//go:build !linux && !windows

package commands

import (
	"os"
	"syscall"
)

// hardenParentProcess is a no-op off Linux; the equivalent parent-protection
// primitives are added per-platform in Phase 5.
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
