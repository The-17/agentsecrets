//go:build windows

package commands

import (
	"os"
	"syscall"
)

// hardenParentProcess is a no-op on Windows; the AppContainer / low-integrity
// equivalent is added in Phase 5.
func hardenParentProcess() {}

// childSysProcAttr leaves the child in its own process group so Ctrl-C is not
// delivered to it implicitly.
func childSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: 0x00000200} // CREATE_NEW_PROCESS_GROUP
}

// isTerminal reports whether f is attached to a terminal.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
