//go:build linux

package commands

import (
	"os"
	"syscall"
)

// prSetDumpable is prctl(PR_SET_DUMPABLE).
const prSetDumpable = 4

// hardenParentProcess makes the agentsecrets process itself non-dumpable.
//
// The child we are about to spawn runs as the same user and is our descendant, so
// by default it can read our memory (/proc/<ppid>/mem, process_vm_readv) and drive
// our already-authenticated keychain-auth socket. Marking ourselves non-dumpable
// makes those require CAP_SYS_PTRACE, which the child does not have.
func hardenParentProcess() {
	_, _, _ = syscall.Syscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0)
}

// childSysProcAttr detaches the child from our controlling terminal. It keeps the
// inherited stdin/stdout/stderr file descriptors but leaves the child with no
// controlling tty, so it cannot open /dev/tty to print secrets around our masking.
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
