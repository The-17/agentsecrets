package commands

import (
	"strings"
	"testing"
)

// TestBridgeWriteVerbsAreRefusedByDefault proves a model-facing bridge call
// cannot mutate state unless a human enabled it. This is the bridge half of the
// permission model; pkg/mcp covers the Go server half.
func TestBridgeWriteVerbsAreRefusedByDefault(t *testing.T) {
	t.Setenv(EnvBridgeAllowWrites, "")

	want := []string{
		"secrets.set", "secrets.delete", "secrets.pull", "secrets.push",
		"project.create", "project.delete", "project.update", "project.use",
		"workspace.create", "workspace.switch",
		"agent.delete", "agent.token_issue",
	}
	for _, verb := range want {
		if !bridgeWrites[verb] {
			t.Errorf("%q is not classified as a write verb; it would be reachable by an injected instruction", verb)
		}
	}
}

// TestBridgeReadVerbsStayOpen proves the guard does not break the read surface
// the bridge exists for.
func TestBridgeReadVerbsStayOpen(t *testing.T) {
	t.Setenv(EnvBridgeAllowWrites, "")

	for _, verb := range []string{
		"ping", "status", "secrets.list", "secrets.diff",
		"project.list", "workspace.list", "workspace.members",
		"agent.list", "logs.list", "logs.summary", "logs.detail",
		"proxy.call", "proxy.status",
	} {
		if bridgeWrites[verb] {
			t.Errorf("%q is classified as a write; reads must stay available", verb)
		}
	}
}

// TestBridgeAllowlistCannotBeReached proves there is no bridge verb that edits
// the allowlist. Widening egress is the highest-value action for an attacker,
// and the bridge must simply not offer it.
func TestBridgeAllowlistCannotBeReached(t *testing.T) {
	for _, verb := range bridgeVerbs {
		lower := strings.ToLower(verb)
		if strings.Contains(lower, "allowlist") {
			t.Errorf("bridge exposes %q; allowlist edits must stay human-only", verb)
		}
	}
}

// TestBridgeSwitchFailsClosed proves a near-miss value does not open writes.
func TestBridgeSwitchFailsClosed(t *testing.T) {
	for _, v := range []string{"1", "yes", "", "enabled", "tru"} {
		t.Setenv(EnvBridgeAllowWrites, v)
		if bridgeAllowWrites() {
			t.Errorf("%q enabled bridge writes; want fail closed", v)
		}
	}
	t.Setenv(EnvBridgeAllowWrites, "true")
	if !bridgeAllowWrites() {
		t.Error("exact \"true\" did not enable writes")
	}
}

// TestBridgeTokenIssueIsTreatedAsWrite proves token minting is gated. Minting
// is not destructive, but it produces a durable credential, which is precisely
// what an injected instruction would ask for.
func TestBridgeTokenIssueIsTreatedAsWrite(t *testing.T) {
	if !bridgeWrites["agent.token_issue"] {
		t.Fatal("agent.token_issue is not gated; a model could mint a durable token")
	}
}
