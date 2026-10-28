package keychainauth

import (
	"strings"
	"testing"
)

// The user-mode daemon must inherit the caller's XDG paths untouched.
//
// An earlier version pinned them to ~/.agentsecrets. That gave the daemon a
// trust store nobody else wrote (so it denied the binary it had just been told
// to authorize) and a fresh keychain.key (so every stored value failed to
// decrypt and the user was silently logged out). This test fails the moment
// anyone reintroduces an override.
func TestDaemonEnvKeepsCallerXDGPaths(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/caller-config")
	t.Setenv("XDG_DATA_HOME", "/tmp/caller-data")

	env := daemonEnv()

	got := make(map[string]string, len(env))
	for _, entry := range env {
		if key, value, ok := strings.Cut(entry, "="); ok {
			got[key] = value
		}
	}

	if got["XDG_CONFIG_HOME"] != "/tmp/caller-config" {
		t.Errorf("daemon XDG_CONFIG_HOME = %q, want the caller's /tmp/caller-config: the daemon would read a different trust store than the one authorize wrote", got["XDG_CONFIG_HOME"])
	}
	if got["XDG_DATA_HOME"] != "/tmp/caller-data" {
		t.Errorf("daemon XDG_DATA_HOME = %q, want the caller's /tmp/caller-data: the daemon would use a different keychain.key and fail to decrypt stored secrets", got["XDG_DATA_HOME"])
	}
}
