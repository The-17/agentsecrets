package gateway

import "testing"

func TestSelectRejectsConflictingEnvModes(t *testing.T) {
	t.Setenv(envMode, string(ModeCloud))
	t.Setenv(envUseCloud, "false")
	if _, err := Select(""); err == nil {
		t.Fatal("conflicting mode variables must fail instead of silently picking one")
	}
}

func TestSelectRejectsMalformedUseCloud(t *testing.T) {
	t.Setenv(envMode, "")
	t.Setenv(envUseCloud, "yes")
	if _, err := Select(""); err == nil {
		t.Fatal("a malformed use-cloud value must fail instead of falling through")
	}
}

func TestSelectAcceptsUseCloudFalse(t *testing.T) {
	t.Setenv(envMode, "")
	t.Setenv(envUseCloud, "false")
	sel, err := Select("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sel.Mode != ModeLocal {
		t.Errorf("got %q, want local", sel.Mode)
	}
}

func TestStoredModeIsValidated(t *testing.T) {
	if _, err := parseModeValue("cloudy", "project config"); err == nil {
		t.Fatal("an unknown stored mode must fail instead of reaching the router as a new Mode value")
	}
}
