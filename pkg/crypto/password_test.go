package crypto

import (
	"strings"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	pw, err := GeneratePassword(32)
	if err != nil {
		t.Fatalf("GeneratePassword: %v", err)
	}
	if len(pw) == 0 {
		t.Error("empty password")
	}
	if strings.ContainsAny(pw, "+/=") {
		t.Errorf("password not URL-safe base64: %q", pw)
	}

	other, err := GeneratePassword(32)
	if err != nil {
		t.Fatal(err)
	}
	if pw == other {
		t.Error("two generated passwords must differ")
	}

	if _, err := GeneratePassword(0); err == nil {
		t.Error("expected error for zero length")
	}
	if _, err := GeneratePassword(512); err == nil {
		t.Error("expected error for oversized length")
	}
}
