package keychainauth

import (
	"errors"
	"strings"
	"testing"
)

func TestUserMessage_DaemonDenied(t *testing.T) {
	tests := []struct {
		reason   reasonCode
		contains []string
	}{
		// The unregistered/hash-mismatch cases must point at the self-healing
		// path and never at a bare `keychain-auth` command: keychain-auth is
		// installed outside PATH (and sudo's secure_path), so that instruction
		// used to strand users with "command not found".
		{reasonUnregisteredBinary, []string{"agentsecrets doctor", "not yet authorized"}},
		{reasonHashMismatch, []string{"agentsecrets doctor", "changed since it was authorized"}},
		{reasonActionNotInPolicy, []string{"agentsecrets doctor"}},
		{reasonServiceNotAllowed, []string{"agentsecrets doctor"}},
		{reasonTargetNotAllowed, []string{"policy does not allow access"}},
		{reasonMalformedRequest, []string{"malformed request"}},
		{reasonInternalError, []string{"agentsecrets doctor"}},
		{reasonCode("unknown_reason"), []string{"unknown_reason", "agentsecrets doctor"}},
	}

	for _, tt := range tests {
		t.Run(string(tt.reason), func(t *testing.T) {
			err := &DaemonDeniedError{Reason: tt.reason}
			got := UserMessage(err)
			for _, want := range tt.contains {
				if !strings.Contains(got, want) {
					t.Errorf("UserMessage() = %q, want it to contain %q", got, want)
				}
			}
		})
	}
}

// TestDeniedMessage_NeverBareKeychainAuth guards the exact regression that cost
// users hours: recovery guidance telling them to run `sudo keychain-auth ...`,
// which fails with "command not found" because keychain-auth is not on PATH, and
// certainly not on sudo's secure_path.
func TestDeniedMessage_NeverBareKeychainAuth(t *testing.T) {
	err := &DaemonDeniedError{Reason: reasonUnregisteredBinary}
	got := UserMessage(err)
	if strings.Contains(got, "sudo keychain-auth ") {
		t.Errorf("message must not instruct a bare `sudo keychain-auth` command (not on secure_path):\n%s", got)
	}
	// Any `keychain-auth` invocation in the guidance must carry a path separator
	// (absolute path), never a bare command word.
	for _, line := range strings.Split(got, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "keychain-auth ") && !strings.Contains(trimmed, "/") {
			t.Errorf("message references keychain-auth without an absolute path: %q", line)
		}
	}
}

func TestDaemonDeniedError_Checks(t *testing.T) {
	unreg := &DaemonDeniedError{Reason: reasonUnregisteredBinary}
	if !unreg.IsUnregistered() {
		t.Error("IsUnregistered() should be true for unregistered_binary_pending_approval")
	}
	if unreg.IsHashMismatch() {
		t.Error("IsHashMismatch() should be false for unregistered_binary_pending_approval")
	}

	hash := &DaemonDeniedError{Reason: reasonHashMismatch}
	if hash.IsUnregistered() {
		t.Error("IsUnregistered() should be false for hash_mismatch_during_fork")
	}
	if !hash.IsHashMismatch() {
		t.Error("IsHashMismatch() should be true for hash_mismatch_during_fork")
	}
}

func TestUserMessage_DaemonNotRunning(t *testing.T) {
	err := &DaemonNotRunningError{SocketPath: "/tmp/sock", Cause: errors.New("conn refused")}
	got := UserMessage(err)
	if !strings.Contains(got, "/tmp/sock") {
		t.Errorf("Expected message to contain socket path, got: %s", got)
	}
	if !strings.Contains(got, "agentsecrets doctor") {
		t.Errorf("Expected message to point at 'agentsecrets doctor', got: %s", got)
	}
}
