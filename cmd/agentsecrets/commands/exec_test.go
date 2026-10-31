package commands

import (
	"encoding/json"
	"testing"
)

// Regression for V4-LOC-022. The v4 runbook sends {"keys":["PLAIN_KEY"]} with
// no protocolVersion field. That must parse into the `keys` alias and a zero
// version (which exec treats as the default) rather than being rejected.
func TestExecRequestAcceptsKeysAliasAndDefaultVersion(t *testing.T) {
	var req ExecRequest
	if err := json.Unmarshal([]byte(`{"keys":["PLAIN_KEY"]}`), &req); err != nil {
		t.Fatalf("unmarshal runbook stdin: %v", err)
	}
	if req.ProtocolVersion != 0 {
		t.Errorf("ProtocolVersion = %d, want 0 (default)", req.ProtocolVersion)
	}
	if len(req.Keys) != 1 || req.Keys[0] != "PLAIN_KEY" {
		t.Errorf("Keys = %v, want [PLAIN_KEY]", req.Keys)
	}

	// The canonical `ids` form still parses.
	var req2 ExecRequest
	if err := json.Unmarshal([]byte(`{"protocolVersion":1,"ids":["A","B"]}`), &req2); err != nil {
		t.Fatalf("unmarshal ids form: %v", err)
	}
	if req2.ProtocolVersion != 1 || len(req2.IDs) != 2 || req2.IDs[0] != "A" {
		t.Errorf("ids form parsed as version=%d ids=%v", req2.ProtocolVersion, req2.IDs)
	}
}
