package keychainauth

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// DaemonDeniedError is returned when keychain-auth denies a connection or request.
type DaemonDeniedError struct {
	Reason reasonCode
}

func (e *DaemonDeniedError) Error() string {
	return fmt.Sprintf("keychain-auth denied request: %s", e.Reason)
}

// IsUnregistered returns true if the denial was due to an unregistered binary.
func (e *DaemonDeniedError) IsUnregistered() bool {
	return e.Reason == reasonUnregisteredBinary
}

// IsHashMismatch returns true if the denial was due to a binary hash mismatch during fork.
func (e *DaemonDeniedError) IsHashMismatch() bool {
	return e.Reason == reasonHashMismatch
}

// DaemonNotRunningError is returned when the keychain-auth socket does not exist
// or the connection is refused.
type DaemonNotRunningError struct {
	SocketPath string
	Cause      error
}

func (e *DaemonNotRunningError) Error() string {
	return "keychain-auth daemon is not running"
}

func (e *DaemonNotRunningError) Unwrap() error {
	return e.Cause
}

// UserMessage returns the full user-facing error text for keychain-auth errors.
// These messages should explain what happened and what to do next.
func UserMessage(err error) string {
	switch e := err.(type) {
	case *DaemonDeniedError:
		return deniedMessage(e.Reason)
	case *DaemonNotRunningError:
		if e.Cause != nil && (os.IsPermission(e.Cause) || strings.Contains(e.Cause.Error(), "permission denied")) {
			return "Permission denied connecting to keychain-auth socket.\n" +
				"Your user is not authorized or your active shell group membership is not active.\n" +
				"Please run:\n" +
				"  newgrp agentgroup\n" +
				"Or restart your terminal session."
		}
		return daemonNotRunningMessage(e.SocketPath)
	default:
		return err.Error()
	}
}

func getSelfPath() string {
	selfPath, err := os.Executable()
	if err == nil {
		if resolved, err := filepath.EvalSymlinks(selfPath); err == nil {
			return resolved
		}
		return selfPath
	}
	return "agentsecrets"
}

// manualRepairHint returns the exact commands that will work on this machine, for
// the rare case where automatic repair failed and the user must intervene.
//
// It resolves the keychain-auth binary to an absolute path on purpose. keychain-auth
// is commonly installed under ~/.agentsecrets/bin, which is not on PATH and is not in
// sudo's secure_path — so a bare `sudo keychain-auth ...` fails with "command not
// found" and strands the user. It also only suggests sudo/systemctl when the daemon
// actually runs in system mode.
func manualRepairHint() string {
	selfPath := getSelfPath()
	kcPath := findBestDaemon()
	if kcPath == "" {
		return "  agentsecrets doctor\n\n" +
			"keychain-auth could not be located. 'agentsecrets doctor' will install it."
	}

	elevate := ""
	restart := fmt.Sprintf("  %s start", kcPath)
	if runtime.GOOS != "windows" && requiresSudoForRegistration(kcPath) {
		elevate = "sudo "
		if _, err := os.Stat("/etc/systemd/system/keychain-auth.service"); err == nil {
			restart = "  sudo systemctl restart keychain-auth"
		} else {
			restart = fmt.Sprintf("  sudo %s start", kcPath)
		}
	}

	return fmt.Sprintf("  %s%s authorize %q %s\n%s", elevate, kcPath, selfPath, serviceName, restart)
}

func deniedMessage(reason reasonCode) string {
	switch reason {
	case reasonUnregisteredBinary:
		return "This AgentSecrets binary is not yet authorized with keychain-auth.\n\n" +
			"Fix it automatically:\n" +
			"  agentsecrets doctor\n\n" +
			"Or authorize it manually:\n" + manualRepairHint()
	case reasonHashMismatch:
		return "Security check: this AgentSecrets binary changed since it was authorized.\n" +
			"This is expected right after an upgrade.\n\n" +
			"Fix it automatically:\n" +
			"  agentsecrets doctor\n\n" +
			"Or re-authorize it manually:\n" + manualRepairHint()
	case reasonActionNotInPolicy:
		return "keychain-auth policy does not allow this operation for AgentSecrets.\n" +
			"Run 'agentsecrets doctor' to inspect and repair the policy."
	case reasonServiceNotAllowed:
		return "keychain-auth policy does not allow AgentSecrets to access this service namespace.\n" +
			"Run 'agentsecrets doctor' to inspect and repair the policy."
	case reasonTargetNotAllowed:
		return "keychain-auth policy does not allow access to this secret.\n" +
			"Check your keychain-auth configuration."
	case reasonMalformedRequest:
		return "keychain-auth received a malformed request. This is a bug — please report it."
	case reasonInternalError:
		return "keychain-auth encountered an internal error.\n" +
			"Run 'agentsecrets doctor' to restart it."
	default:
		return fmt.Sprintf("keychain-auth denied the request: %s\n"+
			"Run 'agentsecrets doctor' to diagnose and repair.", reason)
	}
}

func daemonNotRunningMessage(socketPath string) string {
	return fmt.Sprintf(`keychain-auth daemon is not running.

AgentSecrets requires keychain-auth to read secrets securely.

Fix it automatically:
  agentsecrets doctor

Socket expected at: %s`, socketPath)
}
