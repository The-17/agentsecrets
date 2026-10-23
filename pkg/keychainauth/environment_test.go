package keychainauth

import "testing"

// TestFormatTargetAcceptsCustomEnvironments proves the keychain namespaces by
// whatever environment the CLI resolved, with no allowlist. A custom environment
// therefore gets its own entries, separate from the standard three, so switching
// to it switches the whole local store.
func TestFormatTargetAcceptsCustomEnvironments(t *testing.T) {
	cases := []struct {
		env  string
		want string
	}{
		{"development", "prj-1:development:STRIPE_KEY"},
		{"qa", "prj-1:qa:STRIPE_KEY"},
		{"preview-pr-12", "prj-1:preview-pr-12:STRIPE_KEY"},
		{"", "prj-1:development:STRIPE_KEY"},
	}
	for _, tc := range cases {
		if got := formatTarget("prj-1", tc.env, "STRIPE_KEY"); got != tc.want {
			t.Errorf("formatTarget(env=%q) = %q, want %q", tc.env, got, tc.want)
		}
	}
}

// TestFormatPrefixIsolatesCustomEnvironments proves a list in one environment
// cannot see another's keys. The prefix ends at the colon, so "qa" does not
// match "qa2".
func TestFormatPrefixIsolatesCustomEnvironments(t *testing.T) {
	qa := formatPrefix("prj-1", "qa")
	qa2 := formatPrefix("prj-1", "qa2")

	if qa == qa2 {
		t.Fatalf("qa and qa2 share the prefix %q", qa)
	}
	if qa != "prj-1:qa:" {
		t.Fatalf("prefix = %q, want prj-1:qa:", qa)
	}
	// A key stored under qa2 must not be listed under qa.
	if got := stripPrefix("prj-1:qa2:KEY", qa); got != "" {
		t.Fatalf("stripPrefix matched a qa2 key under qa: %q", got)
	}
}
