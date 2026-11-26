package telemetry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetTelemetryState(t *testing.T) {
	t.Helper()
	mu.Lock()
	data = nil
	dirty = false
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		data = nil
		dirty = false
		mu.Unlock()
	})
}

// TestDaySnapshotExcludesIdentifiers pins the wire contract. Telemetry stays
// useful for product decisions, but it must not carry anything that identifies
// a person, a project, or a workspace.
func TestDaySnapshotExcludesIdentifiers(t *testing.T) {
	resetTelemetryState(t)

	day := &Day{
		CliVersion:           "3.4.0",
		OS:                   "linux",
		Arch:                 "amd64",
		ProxyCalls:           7,
		ProxyBlocked:         1,
		SecretsResolved:      12,
		WorkspaceType:        "team",
		WorkspaceMemberCount: 5,
		CommandExecutions:    map[string]int{"secrets pull": 2},
	}
	payload, err := json.Marshal(daySnapshot{Day: day, Date: "2026-11-26"})
	if err != nil {
		t.Fatal(err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"user_email", "project_id", "workspace_id", "active_environment", "typos"}
	for _, key := range forbidden {
		if _, ok := fields[key]; ok {
			t.Errorf("telemetry payload contains identifying field %q", key)
		}
	}
	required := []string{"cli_version", "os", "arch", "proxy_calls", "secrets_resolved", "workspace_type", "date"}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			t.Errorf("telemetry payload is missing aggregate field %q", key)
		}
	}
}

// TestLocalTelemetryFileExcludesIdentifiers checks the stored file as well as
// the wire shape. A stale record must not survive on disk.
func TestLocalTelemetryFileExcludesIdentifiers(t *testing.T) {
	resetTelemetryState(t)

	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	if err := os.Setenv("HOME", tmpDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Setenv("HOME", origHome) })

	RecordCommand("secrets pull")
	RecordProxyCall()
	if err := Flush(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(tmpDir, ".agentsecrets", "telemetry.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"user_email", "project_id", "workspace_id", "active_environment", "typos"} {
		if strings.Contains(string(raw), marker) {
			t.Errorf("local telemetry file contains %q", marker)
		}
	}
}
