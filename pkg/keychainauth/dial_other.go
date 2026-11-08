//go:build !windows

package keychainauth

import (
	"net"
)

// dialCLOEXEC connects to a Unix domain socket on all non-Windows platforms
// (Linux, macOS, BSD). Go's runtime already opens sockets with O_CLOEXEC set,
// so no manual syscall handling is needed to keep the fd out of child processes.
func dialCLOEXEC(sockPath string) (net.Conn, error) {
	return net.Dial("unix", sockPath)
}

// isPipeBusy is always false off Windows. ERROR_PIPE_BUSY is a Windows named
// pipe condition; a Unix socket dial failure is a genuinely unreachable daemon.
func isPipeBusy(err error) bool {
	return false
}
