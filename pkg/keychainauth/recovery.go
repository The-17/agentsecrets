package keychainauth

import (
	"errors"
	"fmt"
	"sync"
)

// This file holds the transparent-recovery machinery: the primitive that makes a
// binary genuinely usable by the daemon, and the guard that lets an ordinary
// command repair itself instead of printing shell commands at the user.

// RegisterAndActivate makes this exact binary usable by the daemon and proves it.
// Every recovery path uses it, so "authorize a binary" always means the same thing:
// bring the daemon binary up to date, authorize, restart, and verify.
func RegisterAndActivate() error {
	kcPath, err := EnsureInstalled()
	if err != nil {
		return err
	}
	// Promote the daemon binary BEFORE the restart below. The restart runs whatever
	// the service points at, so restarting first would relaunch a stale build.
	if err := ensureSystemDaemonBinary(kcPath); err != nil {
		return err
	}
	// EnsureRegistered authorizes, restarts, and verifies the daemon accepts us.
	return EnsureRegistered(kcPath)
}

// probeDaemonGrant issues one lightweight, side-effect-free request to confirm the
// daemon's live policy grants this binary access.
//
// It deliberately bypasses the request-time auto-repair wrapper: it is called from
// diagnosis and from recovery verification, where a denial is the answer we want to
// observe, not a trigger for another repair.
func probeDaemonGrant() error {
	_, err := sendRequestOnce(request{
		Type:    typeRequest,
		Action:  actionSearch,
		Service: serviceName,
		Targets: []string{"__agentsecrets_verify__:"},
	})
	return err
}

// isRegistrationDenial reports whether err is a denial that re-registering can fix:
// an unregistered binary, or one whose hash changed since it was authorized (the
// normal state immediately after an upgrade).
func isRegistrationDenial(err error) bool {
	var denied *DaemonDeniedError
	if !errors.As(err, &denied) {
		return false
	}
	return denied.IsUnregistered() || denied.IsHashMismatch()
}

// Request-time repair is attempted at most once per process. Re-entrancy matters:
// the repair itself performs daemon requests, and those must not recurse back into
// repair. A plain flag (rather than sync.Once) is used so a re-entrant call returns
// immediately instead of deadlocking on an in-flight Once.
var (
	repairMu         sync.Mutex
	repairAttempted  bool
	repairInProgress bool

	// AutoRepairNotice, when set, presents a request-time repair to the user. It is
	// handed the repair to run, so the CLI can show why work is happening (and the
	// binary being authorized) and run it under a progress indicator. Passing the
	// repair in — rather than just a notice string — keeps the presentation in the
	// CLI while this package stays free of any UI dependency. Left nil by
	// non-interactive callers, which then run the repair directly.
	AutoRepairNotice func(reason string, repair func() error) error

	// DisableAutoRepair turns off request-time self-healing. Set for machine-facing
	// paths (`mcp serve`, `exec`) where an interactive sudo prompt is never wanted.
	DisableAutoRepair bool
)

var errRepairUnavailable = fmt.Errorf("automatic repair already attempted")

// tryRegistrationRepair performs a single self-healing attempt for a registration
// denial. Returns nil when the repair succeeded and the caller should retry.
func tryRegistrationRepair() error {
	if DisableAutoRepair {
		return errRepairUnavailable
	}

	repairMu.Lock()
	if repairAttempted || repairInProgress {
		repairMu.Unlock()
		return errRepairUnavailable
	}
	repairInProgress = true
	repairMu.Unlock()

	defer func() {
		repairMu.Lock()
		repairInProgress = false
		repairAttempted = true
		repairMu.Unlock()
	}()

	const reason = "This AgentSecrets binary needs to be re-authorized with keychain-auth"
	if AutoRepairNotice != nil {
		return AutoRepairNotice(reason, RegisterAndActivate)
	}
	return RegisterAndActivate()
}

// ResetAutoRepairState clears the once-per-process repair guard. Used by tests.
func ResetAutoRepairState() {
	repairMu.Lock()
	repairAttempted = false
	repairInProgress = false
	repairMu.Unlock()
}
