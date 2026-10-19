//go:build !windows

package proxy

import (
	"os"
	"syscall"
)

// IsProcessAlive checks if a process with the given PID is running.
func IsProcessAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds; send signal 0 to probe.
	err = p.Signal(syscall.Signal(0))
	return err == nil
}

// TerminateProcess sends a SIGTERM signal to gracefully stop the process.
func TerminateProcess(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Signal(syscall.SIGTERM)
}
