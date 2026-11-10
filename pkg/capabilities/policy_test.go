package capabilities

import (
	"encoding/json"
	"testing"
)

// TestAgentCapabilities_CnfKeyInsideCapabilities proves the DPoP public key
// rides inside the capabilities dict, never as a top-level field. The control
// plane's AgentCreateSchema uses extra="forbid", so a top-level cnf_key on the
// registration request would be rejected with a 422 and brick every PoP mint.
func TestAgentCapabilities_CnfKeyInsideCapabilities(t *testing.T) {
	pub := []byte{0x01, 0x02, 0x03, 0x04}
	caps := AgentCapabilities{ConfirmationKey: pub}
	b, err := json.Marshal(caps)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if want := `"cnf_key":"AQIDBA=="`; !containsSub(s, want) {
		t.Fatalf("cnf_key must serialize as base64 inside the capabilities object; got %s (want substring %q)", s, want)
	}
	// Decoding back must round-trip the public key bytes exactly.
	var round AgentCapabilities
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	if string(round.ConfirmationKey) != string(pub) {
		t.Fatalf("ConfirmationKey did not round-trip: got %x want %x", round.ConfirmationKey, pub)
	}
}

// TestAgentCapabilities_CnfKeyOmittedWhenEmpty proves legacy registrations are
// byte-for-byte unchanged: no ConfirmationKey means no cnf_key on the wire, so
// the resolver's ParseConfirmationKey sees nil and the token stays unbound.
func TestAgentCapabilities_CnfKeyOmittedWhenEmpty(t *testing.T) {
	caps := AgentCapabilities{CanEnvRead: boolPtr(true)}
	b, err := json.Marshal(caps)
	if err != nil {
		t.Fatal(err)
	}
	if containsSub(string(b), "cnf_key") {
		t.Fatalf("cnf_key must be omitted when empty; got %s", string(b))
	}
}

func containsSub(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func boolPtr(b bool) *bool { return &b }
