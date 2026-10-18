package commands

import "testing"

// The telemetry command name must be the canonical Cobra path, not the first
// argv token: noun-group invocations have to keep their action, and typos must
// stay visible instead of collapsing into the root or a group bucket.
func TestResolveCommandName(t *testing.T) {
	registerAliases()

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"bare root", nil, "root"},
		{"single command", []string{"status"}, "status"},
		{"noun then action", []string{"secrets", "pull"}, "secrets pull"},
		{"action with argument", []string{"secrets", "set", "STRIPE_KEY=sk"}, "secrets set"},
		{"three-level path", []string{"agent", "token", "issue", "worker"}, "agent token issue"},
		{"allowlist nested", []string{"workspace", "allowlist", "add", "example.com"}, "workspace allowlist add"},
		{"singular alias", []string{"project", "list"}, "project list"},
		{"shortcut alias", []string{"pull-secrets"}, "pull-secrets"},
		{"trailing flag", []string{"project", "list", "--remote"}, "project list"},
		{"verb without subcommand", []string{"call", "POST", "https://example.com"}, "call"},
		{"typo keeps first token", []string{"statut"}, "statut"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveCommandName(tc.args); got != tc.want {
				t.Fatalf("resolveCommandName(%q) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}