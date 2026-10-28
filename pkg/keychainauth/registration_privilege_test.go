package keychainauth

import "testing"

// An installed systemd unit means the daemon serves /etc/keychain-auth/config.json
// as its own system user, so `authorize` must be elevated. `status --json` reports
// the caller's view and says requires_sudo:false on exactly those hosts, which made
// the CLI register into the caller's store and then watch the daemon deny the
// binary it had just authorized.
func TestInstalledUnitMakesRegistrationPrivileged(t *testing.T) {
	cases := []struct {
		name       string
		statusSays bool
		unitExists bool
		want       bool
	}{
		{"unit installed, status says no elevation", false, true, true},
		{"unit installed, status agrees", true, true, true},
		{"no unit, status asks for elevation", true, false, true},
		{"no unit, status says no elevation", false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := privilegedRegistrationRequired(tc.statusSays, tc.unitExists); got != tc.want {
				t.Errorf("privilegedRegistrationRequired(status=%v, unit=%v) = %v, want %v",
					tc.statusSays, tc.unitExists, got, tc.want)
			}
		})
	}
}
