package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDescribeTokenSource(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(t *testing.T)
		source string
		token  string
	}{
		{
			name:   "none",
			setup:  func(t *testing.T) {},
			source: "none",
			token:  "",
		},
		{
			name: "canonical env outranks aliases",
			setup: func(t *testing.T) {
				t.Setenv("AGENTSECRETS_TOKEN", "canonical_value")
				t.Setenv("AS_AGENT_TOKEN", "alias_value")
			},
			source: "AGENTSECRETS_TOKEN",
			token:  "canonical_value",
		},
		{
			name: "legacy alias reported without value",
			setup: func(t *testing.T) {
				t.Setenv("AS_AGENT_TOKEN", "alias_value")
			},
			source: "AS_AGENT_TOKEN (legacy alias)",
			token:  "alias_value",
		},
		{
			name: "token file",
			setup: func(t *testing.T) {
				p := filepath.Join(t.TempDir(), "token")
				if err := os.WriteFile(p, []byte("file_value\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("AGENTSECRETS_TOKEN_FILE", p)
			},
			source: "AGENTSECRETS_TOKEN_FILE (file)",
			token:  "file_value",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateEnv(t)
			tc.setup(t)

			if got := DescribeTokenSource(); got != tc.source {
				t.Errorf("DescribeTokenSource() = %q, want %q", got, tc.source)
			}
			if got := TokenFromEnv(); got != tc.token {
				t.Errorf("TokenFromEnv() = %q, want %q", got, tc.token)
			}
			// The descriptor must never contain the credential itself.
			if tc.token != "" && strings.Contains(DescribeTokenSource(), tc.token) {
				t.Errorf("token source leaked the credential value: %q", DescribeTokenSource())
			}
		})
	}
}
