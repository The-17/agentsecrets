//go:build windows

package proxy

import (
	"golang.org/x/sys/windows"
)

// IsProcessAlive checks if a process with the given PID is running on Windows.
func IsProcessAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		if err == windows.ERROR_ACCESS_DENIED {
			// Process exists but access is denied (e.g. running under different privilege/user).
			return true
		}
		return false
	}
	defer windows.CloseHandle(h)

	var exitCode uint32
	if err := windows.GetExitCodeProcess(h, &exitCode); err != nil {
		return false
	}
	// STILL_ACTIVE (259) indicates the process is still running.
	return exitCode == 259
}

// TerminateProcess terminates a process on Windows.
func TerminateProcess(pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}
