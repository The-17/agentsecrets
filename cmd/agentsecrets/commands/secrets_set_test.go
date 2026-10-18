package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/secrets"
)

// TestStoredJSONEnvelope locks the `secrets set --output json` shape and proves
// the value itself never appears in machine-readable output.
func TestStoredJSONEnvelope(t *testing.T) {
	const value = "sk_live_do_not_print"
	metas := []secrets.StoredMeta{secrets.DescribeValue("STRIPE_KEY", "development", value)}

	enc, err := storedJSON(metas)
	if err != nil {
		t.Fatalf("storedJSON: %v", err)
	}
	if strings.Contains(string(enc), value) {
		t.Fatalf("value leaked into JSON output: %s", enc)
	}

	var out struct {
		Status  string               `json:"status"`
		Secrets []secrets.StoredMeta `json:"secrets"`
	}
	if err := json.Unmarshal(enc, &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if out.Status != "stored" {
		t.Errorf("status = %q, want %q", out.Status, "stored")
	}
	if len(out.Secrets) != 1 {
		t.Fatalf("got %d secrets, want 1", len(out.Secrets))
	}
	got := out.Secrets[0]
	if got.Key != "STRIPE_KEY" || got.Environment != "development" {
		t.Errorf("got %+v, want STRIPE_KEY/development", got)
	}
	if got.Length != len(value) {
		t.Errorf("length = %d, want %d", got.Length, len(value))
	}
	if got.Fingerprint != secrets.Fingerprint(value) {
		t.Errorf("fingerprint = %q, want %q", got.Fingerprint, secrets.Fingerprint(value))
	}
}

// TestStoredJSONEmptyIsArray ensures a no-op emit produces `[]`, not `null`, so
// a JSON consumer can iterate without a nil check.
func TestStoredJSONEmptyIsArray(t *testing.T) {
	enc, err := storedJSON(nil)
	if err != nil {
		t.Fatalf("storedJSON: %v", err)
	}
	if !strings.Contains(string(enc), `"secrets":[]`) {
		t.Fatalf("want an empty array, got %s", enc)
	}
}

// TestRunSecretsSetValidation exercises the argument and flag guards of
// `secrets set`. Each case fails before any store or keychain access, so the
// test needs no project, no daemon, and no terminal.
func TestRunSecretsSetValidation(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		stdin bool
		gen   bool
		from  string
		xtrct string
		out   string
		envs  bool
		want  string
	}{
		{
			name: "no arguments",
			want: "provide KEY names, KEY=VALUE pairs, or --stdin",
		},
		{
			name:  "two value sources",
			args:  []string{"K"},
			stdin: true,
			gen:   true,
			want:  "use only one value source",
		},
		{
			name: "batch form with a source",
			args: []string{"K=1"},
			gen:  true,
			want: "cannot be combined with --stdin, --generate, or --from-command",
		},
		{
			name:  "extract without from-command",
			args:  []string{"K"},
			xtrct: "data.key",
			want:  "--extract only applies to --from-command",
		},
		{
			name: "unknown output format",
			args: []string{"K"},
			out:  "yaml",
			want: "--output must be",
		},
		{
			name: "all-envs with json",
			args: []string{"K"},
			out:  "json",
			envs: true,
			want: "--all-envs cannot be combined with --output json",
		},
		{
			name: "prompt form without a terminal",
			args: []string{"K"},
			want: "no terminal to prompt for a value",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newSecretsSetTestCommand(t)
			mustSetBool(t, cmd, "stdin", tc.stdin)
			mustSetBool(t, cmd, "generate", tc.gen)
			mustSetString(t, cmd, "from-command", tc.from)
			mustSetString(t, cmd, "extract", tc.xtrct)
			mustSetString(t, cmd, "output", tc.out)
			allEnvs = tc.envs
			t.Cleanup(func() { allEnvs = false })

			err := runSecretsSet(cmd, tc.args)
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// newSecretsSetTestCommand builds a bare command carrying the flags
// runSecretsSet reads, so the test does not depend on package init().
func newSecretsSetTestCommand(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().Bool("stdin", false, "")
	cmd.Flags().Bool("generate", false, "")
	cmd.Flags().String("from-command", "", "")
	cmd.Flags().String("extract", "", "")
	cmd.Flags().String("output", "text", "")
	cmd.Flags().String("env", "", "")
	cmd.Flags().Int("length", 32, "")
	return cmd
}

func mustSetBool(t *testing.T, cmd *cobra.Command, name string, value bool) {
	t.Helper()
	if err := cmd.Flags().Set(name, fmt.Sprintf("%t", value)); err != nil {
		t.Fatalf("set %s: %v", name, err)
	}
}

func mustSetString(t *testing.T, cmd *cobra.Command, name, value string) {
	t.Helper()
	if value == "" {
		return
	}
	if err := cmd.Flags().Set(name, value); err != nil {
		t.Fatalf("set %s: %v", name, err)
	}
}
