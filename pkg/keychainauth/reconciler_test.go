package keychainauth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsRegistrationDenial(t *testing.T) {
	unreg := &DaemonDeniedError{Reason: reasonUnregisteredBinary}
	hash := &DaemonDeniedError{Reason: reasonHashMismatch}
	policy := &DaemonDeniedError{Reason: reasonActionNotInPolicy}
	other := errors.New("socket gone")

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"unregistered", unreg, true},
		{"hash mismatch", hash, true},
		{"wrapped unregistered", fmt.Errorf("read: %w", unreg), true},
		{"policy denial is not a registration issue", policy, false},
		{"unrelated", other, false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isRegistrationDenial(c.err); got != c.want {
				t.Errorf("isRegistrationDenial(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

func TestTryRegistrationRepair_DisabledIsANoop(t *testing.T) {
	DisableAutoRepair = true
	defer func() { DisableAutoRepair = false }()

	called := false
	AutoRepairNotice = func(string, func() error) error { called = true; return nil }
	defer func() { AutoRepairNotice = nil }()

	if err := tryRegistrationRepair(); err == nil {
		t.Fatal("expected repair to be refused when disabled")
	}
	if called {
		t.Error("AutoRepairNotice must not fire when repair is disabled")
	}
}

func TestInspectRegistration_TempStore(t *testing.T) {
	selfPath, err := SelfPath()
	if err != nil {
		t.Fatal(err)
	}
	selfHash, err := computeHash(selfPath)
	if err != nil {
		t.Fatal(err)
	}

	writeStore := func(t *testing.T, path, binPath, binHash string) {
		t.Helper()
		store := `{"registered_binaries":[{"path":"` + binPath + `","hash":"` + binHash + `"}]}`
		if err := os.WriteFile(path, []byte(store), 0600); err != nil {
			t.Fatal(err)
		}
	}

	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")

	t.Run("exact match", func(t *testing.T) {
		writeStore(t, cfg, selfPath, selfHash)
		reg, err := inspectRegistration(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if !reg.PathFound || !reg.HashMatches || reg.StoreReadErr != nil {
			t.Errorf("expected path+hash match, got PathFound=%v HashMatches=%v StoreReadErr=%v", reg.PathFound, reg.HashMatches, reg.StoreReadErr)
		}
	})

	t.Run("hash mismatch after upgrade", func(t *testing.T) {
		writeStore(t, cfg, selfPath, "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
		reg, err := inspectRegistration(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if !reg.PathFound || reg.HashMatches {
			t.Errorf("expected path found but hash mismatch, got PathFound=%v HashMatches=%v", reg.PathFound, reg.HashMatches)
		}
	})

	t.Run("path not in store", func(t *testing.T) {
		writeStore(t, cfg, "/nonexistent/binary", selfHash)
		reg, err := inspectRegistration(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if reg.PathFound {
			t.Error("expected path not found in store")
		}
	})

	t.Run("unreadable store is not fatal", func(t *testing.T) {
		reg, err := inspectRegistration(filepath.Join(dir, "missing.json"))
		if err != nil {
			t.Fatal(err)
		}
		if reg.StoreReadErr == nil {
			t.Error("expected a StoreReadErr for a missing store")
		}
		if reg.PathFound {
			t.Error("no path should be found for an unreadable store")
		}
	})
}

func TestFirstMeaningfulLine(t *testing.T) {
	out := "Error: binary not registered\nUsage:\n  keychain-auth check [path] [service]\nFlags:..."
	if got := firstMeaningfulLine(out); got != "binary not registered" {
		t.Errorf("got %q, want %q", got, "binary not registered")
	}
	if got := firstMeaningfulLine("   \n\n"); got != "" {
		t.Errorf("expected empty for blank output, got %q", got)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"3.2.5", "3.2.5", 0},
		{"3.2.5", "3.2.4", 1},
		{"3.2.4", "3.2.5", -1},
		{"dev", "3.2.5", -1},
		{"3.2.5", "dev", 1},
		{"v3.2.5", "3.2.5", 0},
		{"3.10.0", "3.9.9", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestShortHash(t *testing.T) {
	if got := shortHash("sha256:" + strings.Repeat("ab", 32)); len(got) != 12 {
		t.Errorf("expected 12-char hash prefix, got %q", got)
	}
	if got := shortHash(""); got != "none" {
		t.Errorf("expected 'none' for empty hash, got %q", got)
	}
}
