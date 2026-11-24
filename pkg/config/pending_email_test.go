package config

import "testing"

func TestPendingEmailLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := HomeDirHook
	HomeDirHook = func() (string, error) { return tmpDir, nil }
	defer func() { HomeDirHook = oldHome }()

	if err := InitGlobalConfig(); err != nil {
		t.Fatal(err)
	}
	if got := GetPendingEmail(); got != "" {
		t.Fatalf("unexpected pending email %q", got)
	}
	if err := SetPendingEmail("new@example.com"); err != nil {
		t.Fatal(err)
	}
	if got := GetPendingEmail(); got != "new@example.com" {
		t.Errorf("got %q", got)
	}
	if err := ClearPendingEmail(); err != nil {
		t.Fatal(err)
	}
	if got := GetPendingEmail(); got != "" {
		t.Errorf("marker not cleared, got %q", got)
	}
}

func TestSetEmailClearsMatchingPendingEmail(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := HomeDirHook
	HomeDirHook = func() (string, error) { return tmpDir, nil }
	defer func() { HomeDirHook = oldHome }()

	if err := InitGlobalConfig(); err != nil {
		t.Fatal(err)
	}
	if err := SetPendingEmail("new@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := SetEmail("new@example.com"); err != nil {
		t.Fatal(err)
	}
	if got := GetPendingEmail(); got != "" {
		t.Errorf("successful login should clear the marker, got %q", got)
	}
}
