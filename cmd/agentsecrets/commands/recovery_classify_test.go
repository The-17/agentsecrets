package commands

import (
	"errors"
	"testing"

	"github.com/The-17/agentsecrets/pkg/keychainauth"
)

// A busy named pipe is a live daemon. Classifying it as recoverDaemon would
// remove the socket and restart a healthy daemon on every transient contention
// window, turning a short wait into an outage.
func TestClassifyInitError_DaemonBusyIsNotRecovered(t *testing.T) {
	err := &keychainauth.DaemonBusyError{
		SocketPath: `\\.\pipe\keychain-auth`,
		Cause:      errors.New("All pipe instances are busy"),
	}
	if got := classifyInitError(err); got != recoverNone {
		t.Fatalf("busy daemon classified as %v, want recoverNone", got)
	}
}

func TestClassifyInitError_DaemonNotRunningStillRecovers(t *testing.T) {
	err := &keychainauth.DaemonNotRunningError{
		SocketPath: "/run/keychain-auth/agent.sock",
		Cause:      errors.New("no such file or directory"),
	}
	if got := classifyInitError(err); got != recoverDaemon {
		t.Fatalf("missing daemon classified as %v, want recoverDaemon", got)
	}
}
