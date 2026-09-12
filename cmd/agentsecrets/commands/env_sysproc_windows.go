//go:build windows

package commands

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hardenParentProcess is a documented no-op on Windows.
//
// The Linux/macOS equivalents work because the OS lets a process drop its own
// attachability (PR_SET_DUMPABLE / PT_DENY_ATTACH). Windows has no such switch:
// the object owner implicitly keeps READ_CONTROL and WRITE_DAC, so a same-user
// process can always rewrite our DACL and grant itself PROCESS_VM_READ. Real
// isolation from a same-user peer needs a separate identity (a restricted token or
// AppContainer), which is out of scope here. We therefore do not pretend to protect
// the parent's memory on Windows.
func hardenParentProcess() {}

// childSD roots the child's security descriptor for the lifetime of the process.
// SecurityAttributes stores the descriptor as a uintptr, which the garbage
// collector does not treat as a live pointer; keeping the typed pointer here
// ensures the backing memory survives until CreateProcess reads it.
var childSD *windows.SECURITY_DESCRIPTOR

// childSysProcAttr puts the child in its own process group and, best-effort,
// applies a security descriptor that denies PROCESS_VM_READ to the current user so
// a same-user peer cannot ReadProcessMemory the child's injected secrets.
//
// This RAISES THE BAR; it is not an authoritative boundary. The child's owner keeps
// WRITE_DAC and can rewrite the DACL to re-grant itself the access. If the
// descriptor cannot be built for any reason we fail open and spawn the child
// normally — env must still work.
func childSysProcAttr() *syscall.SysProcAttr {
	base := &syscall.SysProcAttr{CreationFlags: 0x00000200} // CREATE_NEW_PROCESS_GROUP
	if sa, err := denyVMReadAttributes(); err == nil {
		base.ProcessAttributes = sa
	}
	return base
}

// denyVMReadAttributes builds SecurityAttributes whose DACL denies PROCESS_VM_READ
// to the current user and allows everything else. The creator's own process handle
// is granted at CreateProcess time and is unaffected by this DACL, so the parent
// can still wait on and signal the child.
func denyVMReadAttributes() (*syscall.SecurityAttributes, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return nil, err
	}
	defer token.Close()

	tu, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	sid := tu.User.Sid.String()
	if sid == "" {
		return nil, fmt.Errorf("empty user SID")
	}

	// Deny ACEs are evaluated before allow ACEs, so this denies PROCESS_VM_READ
	// (0x0010) while leaving normal same-user management — wait, terminate, query —
	// intact via the trailing allow of PROCESS_ALL_ACCESS (0x1FFFFF).
	sddl := "D:(D;;0x00000010;;;" + sid + ")(A;;0x001FFFFF;;;" + sid + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	childSD = sd

	sa := &syscall.SecurityAttributes{}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	sa.SecurityDescriptor = uintptr(unsafe.Pointer(sd))
	return sa, nil
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

// guardAttachWarning has nothing to report: no preload guard is wired up for
// Windows, so there is no attachment to warn about.
func guardAttachWarning(target string) string { return "" }
