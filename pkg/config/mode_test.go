package config

import "testing"

// TestDefaultModeRoundtrip covers the persisted preference. An unset mode must
// read as "" rather than "local" so the router can distinguish "no choice" from
// an explicit local choice.
func TestDefaultModeRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := HomeDirHook
	HomeDirHook = func() (string, error) { return tmpDir, nil }
	defer func() { HomeDirHook = oldHome }()

	if err := InitGlobalConfig(); err != nil {
		t.Fatalf("InitGlobalConfig: %v", err)
	}

	if got := GetDefaultMode(); got != "" {
		t.Errorf("unset mode = %q, want empty", got)
	}

	if err := SetDefaultMode("cloud"); err != nil {
		t.Fatalf("SetDefaultMode(cloud): %v", err)
	}
	if got := GetDefaultMode(); got != "cloud" {
		t.Errorf("mode = %q, want cloud", got)
	}

	if err := SetDefaultMode("local"); err != nil {
		t.Fatalf("SetDefaultMode(local): %v", err)
	}
	if got := GetDefaultMode(); got != "local" {
		t.Errorf("mode = %q, want local", got)
	}

	if err := SetDefaultMode("hybrid"); err == nil {
		t.Error("expected an error for an unknown mode")
	}
}
