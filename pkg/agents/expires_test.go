package agents

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestParseExpiresInDays covers the human expiry forms accepted by --expires.
func TestParseExpiresInDays(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{"30", 30, false},
		{"30d", 30, false},
		{"90D", 90, false},
		{"1w", 7, false},
		{"2w", 14, false},
		{"6m", 180, false},
		{"1y", 365, false},
		{" 12d ", 12, false},
		{"0", 0, true},
		{"-5d", 0, true},
		{"30h", 0, true},
		{"abc", 0, true},
		{"d", 0, true},
	}
	for _, c := range cases {
		got, err := ParseExpiresInDays(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseExpiresInDays(%q) err=%v, wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("ParseExpiresInDays(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestAgentRequestsUseExpiresInDaysField is the regression test for the CLI/
// server wire drift: the server schemas (AgentCreateSchema / AgentTokenCreateSchema)
// use `expires_in_days: int` with extra="forbid", so the old `expires_in` string
// field made every `agent register --expires` / `agent token issue --expires`
// call fail with 422 "Extra inputs are not permitted".
func TestAgentRequestsUseExpiresInDaysField(t *testing.T) {
	for name, payload := range map[string]any{
		"RegisterRequest":    RegisterRequest{Name: "x", ExpiresInDays: 30},
		"IssueTokenRequest":  IssueTokenRequest{ExpiresInDays: 30},
	} {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		s := string(b)
		if !strings.Contains(s, `"expires_in_days":30`) {
			t.Fatalf("%s payload = %s, must carry expires_in_days", name, s)
		}
		// The legacy field name (a bare "expires_in" key) must be gone.
		if strings.Contains(s, `"expires_in":`) {
			t.Fatalf("%s payload = %s, must not carry legacy expires_in", name, s)
		}
	}
}
