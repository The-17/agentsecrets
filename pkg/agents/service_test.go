package agents

import (
	"encoding/json"
	"testing"

	"github.com/The-17/agentsecrets/pkg/capabilities"
)

// TestRegisterRequest_CnfKeyInsideCapabilities proves the exact wire bytes the
// CLI sends to the control plane: the DPoP public key must be nested under
// "capabilities", not a top-level "cnf_key". A top-level field would trip the
// server's extra="forbid" schema and 422 the registration.
func TestRegisterRequest_CnfKeyInsideCapabilities(t *testing.T) {
	pub := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	req := RegisterRequest{
		Name:        "ci-bot",
		WorkspaceID: "ws_123", // must NOT appear on the wire (json:"-")
		Capabilities: &capabilities.AgentCapabilities{
			ConfirmationKey: pub,
		},
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)

	// WorkspaceID is routing-only and must never leave the process.
	if containsStr(s, "ws_123") {
		t.Fatal("WorkspaceID must not be serialized")
	}
	// The cnf_key must be present, nested under capabilities.
	if !containsStr(s, `"cnf_key":"qrvM3Q=="`) {
		t.Fatalf("expected cnf_key base64 under capabilities; got %s", s)
	}
	// And must NOT be a top-level field.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["cnf_key"]; ok {
		t.Fatal("cnf_key must not be a top-level field on RegisterRequest")
	}
	if _, ok := m["capabilities"]; !ok {
		t.Fatal("capabilities object must be present")
	}
}

// TestRegisterRequest_NoCnfKeyWhenNil proves a non-PoP registration sends no
// cnf_key at all, keeping legacy tokens byte-for-byte unchanged and unbound.
func TestRegisterRequest_NoCnfKeyWhenNil(t *testing.T) {
	req := RegisterRequest{Name: "legacy", Capabilities: &capabilities.AgentCapabilities{}}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if containsStr(string(b), "cnf_key") {
		t.Fatalf("non-PoP registration must omit cnf_key; got %s", string(b))
	}
}

func containsStr(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
