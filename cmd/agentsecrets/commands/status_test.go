package commands

import (
	"errors"
	"testing"
)

func TestStatusVersionDisplay(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    string
	}{
		{"4.0.0-dev", "3.3.6", "4.0.0-dev (dev build)"},
		{"3.2.3", "3.3.6", "3.2.3 (outdated, 3.3.6 available)"},
		{"3.3.6", "3.3.6", "3.3.6 (up to date)"},
		{"3.3.6", "", "3.3.6"},
	}

	for _, tt := range tests {
		if got := statusVersionDisplay(tt.current, tt.latest); got != tt.want {
			t.Errorf("statusVersionDisplay(%q, %q) = %q, want %q", tt.current, tt.latest, got, tt.want)
		}
	}
}

// status is read-only: it prints config and token state. It must never run the
// daemon bootstrap, because that path prompts for sudo (keychain-auth sandbox
// setup) and, in a non-TTY shell, dies with a raw "sudo: unable to read
// password" instead of printing anything.
func TestStatusDoesNotRequireTheDaemon(t *testing.T) {
	if statusCmd.PersistentPreRunE != nil {
		t.Fatal("status must not run daemonOnlyMiddleware: it is read-only and must not trigger keychain/sudo setup")
	}
}

func TestSecretsSyncDisplay(t *testing.T) {
	okDiff := func() (int, int, error) { return 3, 2, nil }
	failing := func() (int, int, error) { return 0, 0, errors.New("boom") }
	called := func() (int, int, error) {
		t.Fatal("diff must not run when the daemon is unavailable")
		return 0, 0, nil
	}

	tests := []struct {
		name          string
		authenticated bool
		daemonUp      bool
		diff          func() (int, int, error)
		want          string
	}{
		{"not logged in", false, true, called, "Login to view"},
		{"daemon down", true, false, called, "Unavailable (keychain-auth daemon not running)"},
		{"in sync", true, true, func() (int, int, error) { return 0, 0, nil }, "No secrets found"},
		{"drift", true, true, okDiff, "3 synced (2 unsynced)"},
		{"diff error", true, true, failing, "Could not check (boom)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := secretsSyncDisplay(tt.authenticated, tt.daemonUp, tt.diff); got != tt.want {
				t.Errorf("secretsSyncDisplay() = %q, want %q", got, tt.want)
			}
		})
	}
}
