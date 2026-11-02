package commands

import (
	"testing"

	"github.com/The-17/agentsecrets/pkg/log"
	"github.com/The-17/agentsecrets/pkg/proxy"
)

// TestEnforcementFilterNeedsLocal pins LOC-015b: filters on an enforcement
// outcome (blocked/redacted/failed) must query the local forensic store, the
// only source that records those decisions. The remote server view drops them.
func TestEnforcementFilterNeedsLocal(t *testing.T) {
	cases := []struct {
		name string
		f    log.Filter
		want bool
	}{
		{"blocked", log.Filter{Blocked: true}, true},
		{"redacted", log.Filter{Redacted: true}, true},
		{"failed", log.Filter{Failed: true}, true},
		{"none", log.Filter{}, false},
		{"agent-only", log.Filter{Agent: "some-agent"}, false},
		{"domain-only", log.Filter{Domain: "api.example.com"}, false},
	}
	for _, c := range cases {
		if got := enforcementFilterNeedsLocal(c.f); got != c.want {
			t.Errorf("%s: enforcementFilterNeedsLocal = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestReplayDecisionFromEvent pins LOC-016's degraded replay path: a
// server-side-only log (no local forensic record) still yields a decision
// instead of failing with "not found".
func TestReplayDecisionFromEvent(t *testing.T) {
	cases := []struct {
		status string
		want   string
	}{
		{"BLOCKED", "BLOCKED"},
		{"FAILED", "BLOCKED"},
		{"PERMITTED", "PERMITTED"},
		{"", "PERMITTED"},
	}
	for _, c := range cases {
		ev := &proxy.AuditEvent{Status: c.status}
		if got := replayDecisionFromEvent(ev); got != c.want {
			t.Errorf("status %q: decision = %q, want %q", c.status, got, c.want)
		}
	}
}
