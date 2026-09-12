//go:build darwin

package commands

import (
	"debug/macho"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ptDenyAttach is ptrace(PT_DENY_ATTACH): it sets P_LNOATTACH on the calling
// process so task_for_pid() and ptrace() against it fail for a same-user caller.
const ptDenyAttach = 31

// hardenParentProcess makes the agentsecrets process itself un-attachable.
//
// The child we are about to spawn runs as the same user and is our descendant.
// Reading another process's memory on macOS already requires task_for_pid(), which
// is gated by root or the debugger entitlement, so the parent's environment is not
// freely readable the way it is on Linux. PT_DENY_ATTACH is defense in depth on top
// of that: it also blocks a debugger from attaching to drive our authenticated
// keychain-auth socket. Best-effort — errors are ignored.
func hardenParentProcess() {
	_, _, _ = syscall.Syscall(syscall.SYS_PTRACE, ptDenyAttach, 0, 0)
}

// childSysProcAttr detaches the child from our controlling terminal. It keeps the
// inherited stdin/stdout/stderr descriptors but leaves the child with no
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

// sandboxArgv is not available on macOS: there is no unprivileged network
// namespace equivalent, and the sandbox-exec profile route is deprecated.
func sandboxArgv(args []string) ([]string, error) {
	return nil, fmt.Errorf("--sandbox is currently supported on Linux only")
}

// guardAttachWarning returns a message when the guard library cannot attach to
// target, or "" when it can (or attachment cannot be determined). On macOS the
// blocker is the hardened runtime: dyld ignores DYLD_INSERT_LIBRARIES for such
// binaries, so the output guard never loads. The child still runs, and its
// environment stays protected by macOS's own task_for_pid gating.
func guardAttachWarning(target string) string {
	if machoHardened(target) {
		return filepath.Base(target) + " uses the hardened runtime; the output guard can't attach, so secret values won't be redacted from its own console writes (its environment stays protected by macOS)"
	}
	return ""
}

// Code-signing constants. The code directory carries a flags word; CS_RUNTIME is
// set when the binary opts into the hardened runtime. The signature blobs are laid
// out big-endian regardless of the Mach-O byte order.
const (
	csRuntime       = 0x10000    // CS_RUNTIME: opted into the hardened runtime
	csMagicEmbedded = 0xfade0cc0 // CSMAGIC_EMBEDDED_SIGNATURE (SuperBlob)
	csMagicCodeDir  = 0xfade0c02 // CSMAGIC_CODEDIRECTORY
	lcCodeSignature = 0x1d       // LC_CODE_SIGNATURE load command
	maxSigBlobs     = 64         // sanity cap on SuperBlob index entries
)

// machoHardened reports whether the Mach-O executable at path is signed with the
// hardened runtime flag set. A parse failure (fat binary, script, unsigned, absent
// signature) returns false: when in doubt we do not warn.
func machoHardened(path string) bool {
	f, err := macho.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	for _, l := range f.Loads {
		raw, ok := l.(macho.LoadBytes)
		if !ok {
			continue
		}
		b := raw.Raw()
		if len(b) < 16 || f.ByteOrder.Uint32(b[0:4]) != lcCodeSignature {
			continue
		}
		dataoff := f.ByteOrder.Uint32(b[8:12])
		return codeSigHasRuntime(path, int64(dataoff))
	}
	return false
}

// codeSigHasRuntime parses the code-signing SuperBlob at off, finds the code
// directory, and reports whether its flags word has CS_RUNTIME set.
func codeSigHasRuntime(path string, off int64) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	var hdr [12]byte
	if _, err := f.ReadAt(hdr[:], off); err != nil {
		return false
	}
	if binary.BigEndian.Uint32(hdr[0:4]) != csMagicEmbedded {
		return false
	}
	count := binary.BigEndian.Uint32(hdr[8:12])
	if count == 0 || count > maxSigBlobs {
		return false
	}

	idx := make([]byte, count*8)
	if _, err := f.ReadAt(idx, off+12); err != nil {
		return false
	}
	for i := uint32(0); i < count; i++ {
		blobOff := binary.BigEndian.Uint32(idx[i*8+4 : i*8+8])
		var bh [16]byte
		if _, err := f.ReadAt(bh[:], off+int64(blobOff)); err != nil {
			continue
		}
		if binary.BigEndian.Uint32(bh[0:4]) != csMagicCodeDir {
			continue
		}
		return binary.BigEndian.Uint32(bh[12:16])&csRuntime != 0
	}
	return false
}
