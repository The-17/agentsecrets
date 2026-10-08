//go:build linux

package commands

import (
	"debug/elf"
	"fmt"
	"os/exec"
	"path/filepath"
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

// childSysProcAttr detaches the child from our controlling terminal and marks
// it to die with us. Setsid leaves the child with no controlling tty, so the
// /dev/tty literal no longer reaches our terminal — but that is session
// hygiene, not containment: the child keeps its inherited fds and can still
// open the concrete pty or /proc/self/fd to write around the maskers. Real
// output containment is the interposer plus --sandbox, not session detach.
// Pdeathsig closes the orphan gap: a secret-bearing child never outlives us.
func childSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL}
}

// sandboxArgv wraps cmd so it runs with no network egress: a private network
// namespace with only loopback. Unprivileged user namespaces make this possible
// without root; the child is mapped to root inside its own namespace so its file
// access is unchanged.
func sandboxArgv(args []string) ([]string, error) {
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		return nil, fmt.Errorf("--sandbox requires 'unshare' (util-linux), not found in PATH")
	}
	return append([]string{unshare, "--user", "--map-root-user", "--net", "--fork", "--"}, args...), nil
}

// guardAttachWarning returns a message when the guard library cannot attach to
// target, or "" when it can. On Linux the blocker is static linking: the dynamic
// loader never runs, so LD_PRELOAD is ignored and the child cannot be made
// non-dumpable. Output is still redacted by the parent-side masker.
func guardAttachWarning(target string) string {
	if isStaticBinary(target) {
		return filepath.Base(target) + " is statically linked; the output guard can't attach, so other processes running as you could read its environment"
	}
	return ""
}

// isStaticBinary reports whether path is a statically linked ELF executable. The
// preload guard cannot attach to one, so its protections do not apply; a static
// binary has no PT_INTERP program header.
func isStaticBinary(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false // scripts and non-ELF: unknown, do not warn
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return false
		}
	}
	return true
}
