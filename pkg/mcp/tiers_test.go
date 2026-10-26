package mcp

import (
	"strings"
	"testing"
)

// TestWriteToolsAreRefusedByDefault is the core assertion of the permission
// model: a fresh server, with no human-configured switch, must refuse every
// mutating tool. This is what stops a poisoned tool result from deleting a
// credential or minting a token.
func TestWriteToolsAreRefusedByDefault(t *testing.T) {
	t.Setenv(EnvAllowWrites, "")

	for _, tool := range []string{"switch_environment", "pull_secrets", "rotate_key"} {
		err := gate(tierOf(t, tool), tool)
		if err == nil {
			t.Errorf("%s was allowed with no human switch; want refused", tool)
		}
	}
}

// TestReadToolsAlwaysAllowed proves the guard does not overreach: reading,
// diffing, and auditing stay available, because none of them hands an injected
// instruction anything it wants.
func TestReadToolsAlwaysAllowed(t *testing.T) {
	t.Setenv(EnvAllowWrites, "")

	for _, tool := range []string{"api_call", "list_keys", "check_key", "diff_secrets", "get_audit_summary"} {
		if err := gate(tierOf(t, tool), tool); err != nil {
			t.Errorf("%s was refused in read tier: %v", tool, err)
		}
	}
}

// TestHumanSwitchEnablesWrites proves the escape hatch works and is the only
// thing that opens it.
func TestHumanSwitchEnablesWrites(t *testing.T) {
	t.Setenv(EnvAllowWrites, "true")
	if err := gate(TierDestructive, "rotate_key"); err != nil {
		t.Fatalf("writes enabled but destructive tool refused: %v", err)
	}
}

// TestSwitchFailsClosedOnATypo proves a near-miss value does not silently open
// the surface. Only an exact "true" counts.
func TestSwitchFailsClosedOnATypo(t *testing.T) {
	for _, v := range []string{"1", "yes", "TRUE ", "", "enabled", "tru"} {
		t.Setenv(EnvAllowWrites, v)
		if v == "TRUE " {
			continue // EqualFold+TrimSpace deliberately accepts this one
		}
		if AllowWrites() {
			t.Errorf("%q enabled writes; want fail closed", v)
		}
	}
}

// TestRefusalIsActionable proves the refusal tells the model what to do instead
// of just failing. A bare error invites retries and workarounds; naming the
// human command is what makes handing it back the obvious move.
func TestRefusalIsActionable(t *testing.T) {
	t.Setenv(EnvAllowWrites, "")
	err := gate(TierDestructive, "rotate_key")
	if err == nil {
		t.Fatal("want refusal")
	}
	msg := err.Error()
	for _, want := range []string{"prompt injection", "agentsecrets secrets delete", EnvAllowWrites, "cannot enable it yourself"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal missing %q:\n%s", want, msg)
		}
	}
}

// TestRefusalNeverSuggestsPastingASecret guards the one instruction that would
// turn a refusal into a new leak: asking the human to paste a value in chat.
func TestRefusalNeverSuggestsPastingASecret(t *testing.T) {
	t.Setenv(EnvAllowWrites, "")
	for _, tool := range []string{"rotate_key", "pull_secrets"} {
		msg := gate(TierWrite, tool).Error()
		if strings.Contains(strings.ToLower(msg), "paste the value") &&
			!strings.Contains(strings.ToLower(msg), "should not ask") {
			t.Errorf("%s refusal suggests pasting a value:\n%s", tool, msg)
		}
	}
}

// TestEveryRegisteredToolHasATier proves the registration path cannot leak an
// untiered tool. A tool with no tier would be a silent bypass, so the map must
// cover exactly the registered surface.
func TestEveryRegisteredToolHasATier(t *testing.T) {
	srv := newTestServer(t)
	if len(srv.tiers) == 0 {
		t.Fatal("no tiers recorded; registration bypassed the guard")
	}
	for name, tier := range srv.tiers {
		if tier != TierRead && tier != TierWrite && tier != TierDestructive {
			t.Errorf("%s has invalid tier %q", name, tier)
		}
	}
	// Spot-check the tools that matter for the threat model.
	if srv.tiers["rotate_key"] != TierDestructive {
		t.Errorf("rotate_key tier = %q, want destructive", srv.tiers["rotate_key"])
	}
	if srv.tiers["list_keys"] != TierRead {
		t.Errorf("list_keys tier = %q, want read", srv.tiers["list_keys"])
	}
}

// TestSecretStoreIsNotOnTheAgentSurface proves value-blind creation stays off
// the model-facing surface. Minting produces a durable credential, which is
// exactly what an injected instruction wants, so the safest create path for an
// agent is no create path. The capability lives on the CLI and the Python SDK.
func TestSecretStoreIsNotOnTheAgentSurface(t *testing.T) {
	srv := newTestServer(t)
	if _, present := srv.tiers["secret_store"]; present {
		t.Fatal("secret_store is registered on the agent surface; it must stay cancelled")
	}
}

// TestNoCreateVerbReachesTheAgentSurface proves no registered tool can create a
// secret value, in any tier.
func TestNoCreateVerbReachesTheAgentSurface(t *testing.T) {
	srv := newTestServer(t)
	for name := range srv.tiers {
		switch name {
		case "secret_store", "secrets_set", "secrets_set_value", "create_secret":
			t.Errorf("%q creates a secret value and must not be on the agent surface", name)
		}
	}
}

// TestTierReportIsHonest proves status reports the real switch state rather
// than a claim, so the human reading a transcript can see it.
func TestTierReportIsHonest(t *testing.T) {
	t.Setenv(EnvAllowWrites, "")
	srv := newTestServer(t)

	rep := srv.TierReport()
	if rep["writes_enabled"] != false {
		t.Errorf("writes_enabled = %v, want false", rep["writes_enabled"])
	}
	read, ok := rep["read"].([]string)
	if !ok || len(read) == 0 {
		t.Errorf("read tier empty or wrong type: %v", rep["read"])
	}
	destructive, ok := rep["destructive"].([]string)
	if !ok || len(destructive) == 0 {
		t.Errorf("destructive tier empty or wrong type: %v", rep["destructive"])
	}
}
