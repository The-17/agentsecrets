package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestMCPServerEntryUsesPublishedBridge locks the default install shape: the
// published npx package. A version pin or an absolute binary path in this entry
// is the bug that forced every user to edit config on each release.
func TestMCPServerEntryUsesPublishedBridge(t *testing.T) {
	entry := mcpServerEntry()

	if got := entry["command"]; got != "npx" {
		t.Errorf("command = %v, want npx", got)
	}
	wantArgs := []string{"-y", "@the-17/agentsecrets-mcp@latest"}
	if got, ok := entry["args"].([]string); !ok || !reflect.DeepEqual(got, wantArgs) {
		t.Errorf("args = %v, want %v", entry["args"], wantArgs)
	}

	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), string(filepath.Separator)+"home") {
		t.Fatalf("entry carries an absolute path: %s", encoded)
	}
}

// TestWriteMCPConfigReplacesOwnEntryAndKeepsOthers proves the installer is
// idempotent and does not clobber other MCP servers in the user's file.
func TestWriteMCPConfigReplacesOwnEntryAndKeepsOthers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	existing := `{
  "mcpServers": {
    "other": {"command": "node", "args": ["server.js"]},
    "agentsecrets": {"command": "/stale/path/agentsecrets", "args": ["mcp", "serve"]}
  },
  "unrelated": {"keep": true}
}`
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	entry := mcpServerEntry()
	if err := writeMCPConfig(path, "agentsecrets", entry); err != nil {
		t.Fatalf("writeMCPConfig: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("invalid JSON written: %v", err)
	}

	servers, ok := raw["mcpServers"].(map[string]interface{})
	if !ok {
		t.Fatal("mcpServers missing or wrong type")
	}
	if _, ok := servers["other"]; !ok {
		t.Error("existing server entry was dropped")
	}
	if _, ok := raw["unrelated"]; !ok {
		t.Error("unrelated config key was dropped")
	}

	ours, ok := servers["agentsecrets"].(map[string]interface{})
	if !ok {
		t.Fatal("agentsecrets entry missing")
	}
	if ours["command"] != "npx" {
		t.Errorf("stale binary path survived: command = %v", ours["command"])
	}
}
