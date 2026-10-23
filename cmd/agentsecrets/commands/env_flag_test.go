package commands

import (
	"strings"
	"testing"
)

// TestEnvFlagRejectsInvalidNames proves `agentsecrets env --env <name>` validates
// before it touches a project or the network. Each case must fail on the name
// rule, not on "no active project", which is the error a valid name reaches.
func TestEnvFlagRejectsInvalidNames(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want string
	}{
		{"space inside", "has space", "invalid environment name"},
		{"leading hyphen", "-lead", "invalid environment name"},
		{"leading digit", "9qa", "invalid environment name"},
		{"too long", strings.Repeat("a", 40), "invalid environment name"},
		{"reserved root", "root", "reserved"},
		{"reserved admin", "admin", "reserved"},
		{"reserved api", "api", "reserved"},
		{"reserved internal", "internal", "reserved"},
		{"reserved default", "default", "reserved"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewEnvCmd()
			err := runEnv(cmd, []string{"--env", tc.env, "--", "echo", "hi"})
			if err == nil {
				t.Fatalf("--env %q was accepted", tc.env)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("--env %q error = %q, want it to contain %q", tc.env, err, tc.want)
			}
		})
	}
}

// TestEnvFlagAcceptsCustomName proves a custom environment passes validation and
// reaches project resolution, which is the boundary this test can observe
// without a configured project or a live server.
func TestEnvFlagAcceptsCustomName(t *testing.T) {
	for _, name := range []string{"qa", "preview-pr-12", "uat", "QA "} {
		t.Run(name, func(t *testing.T) {
			cmd := NewEnvCmd()
			err := runEnv(cmd, []string{"--env", name, "--", "echo", "hi"})
			if err == nil {
				return
			}
			if strings.Contains(err.Error(), "invalid environment name") ||
				strings.Contains(err.Error(), "reserved environment name") ||
				strings.Contains(err.Error(), "environment name is required") {
				t.Fatalf("--env %q was rejected by the name rule: %v", name, err)
			}
		})
	}
}

// TestEnvFlagEqualsForm proves the `--env=qa` spelling parses the same way as the
// two-argument form, since DisableFlagParsing means cobra does not help here.
func TestEnvFlagEqualsForm(t *testing.T) {
	cmd := NewEnvCmd()
	err := runEnv(cmd, []string{"--env=has space", "--", "echo", "hi"})
	if err == nil || !strings.Contains(err.Error(), "invalid environment name") {
		t.Fatalf("--env=has space error = %v, want the name rule to reject it", err)
	}
}

// TestEnvFlagEmptyMeansActive documents that `--env ""` is not a name: it means
// "use the active environment", so it must never be reported as an invalid one.
func TestEnvFlagEmptyMeansActive(t *testing.T) {
	cmd := NewEnvCmd()
	err := runEnv(cmd, []string{"--env", "", "--", "echo", "hi"})
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), "environment name is required") {
		t.Fatalf("empty --env was treated as a name: %v", err)
	}
}
