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
		Typos:                map[string]int{"command": 2},
	}
	payload, err := json.Marshal(daySnapshot{Day: day, Date: "2026-11-26"})
	if err != nil {
		t.Fatal(err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"user_email", "project_id", "workspace_id", "active_environment"}
	for _, key := range forbidden {
		if _, ok := fields[key]; ok {
			t.Errorf("telemetry payload contains identifying field %q", key)
		}
	}
	required := []string{"cli_version", "os", "arch", "proxy_calls", "secrets_resolved", "workspace_type", "date", "typos"}
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
	for _, marker := range []string{"user_email", "project_id", "workspace_id", "active_environment"} {
		if strings.Contains(string(raw), marker) {
			t.Errorf("local telemetry file contains %q", marker)
		}
	}
}

// TestTypoKeysAreBoundedCategories proves typo metrics survive without the
// raw user input being stored. The typed argument makes a free-form string
// impossible at compile time.
func TestTypoKeysAreBoundedCategories(t *testing.T) {
	resetTelemetryState(t)

	RecordTypo(TypoCommand)
	RecordTypo(TypoCommand)
	RecordTypo(TypoSecretKey)
	RecordTypo("")

	mu.Lock()
	d := currentDayLocked()
	mu.Unlock()

	allowed := map[string]bool{
		string(TypoCommand): true, string(TypoFlag): true, string(TypoSecretKey): true,
		string(TypoEnvironment): true, string(TypoOther): true,
	}
	for key := range d.Typos {
		if !allowed[key] {
			t.Errorf("typo key %q is not a bounded category", key)
		}
	}
	if d.Typos[string(TypoCommand)] != 2 {
		t.Errorf("command typos = %d, want 2", d.Typos[string(TypoCommand)])
	}
	if d.Typos[string(TypoOther)] != 1 {
		t.Errorf("other typos = %d, want 1", d.Typos[string(TypoOther)])
	}
}
