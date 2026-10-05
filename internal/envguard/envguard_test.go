package envguard

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withFakeLib points discovery at a temp dir containing (or not containing) a
// fake guard library, restoring the real search afterwards. The fake is pinned
// (hash registered) so verification passes unless the test tampers with it.
func withFakeLib(t *testing.T, present bool) string {
	t.Helper()
	dir := t.TempDir()
	prev := searchDirsHook
	searchDirsHook = func() []string { return []string{dir} }
	t.Cleanup(func() { searchDirsHook = prev })

	if present {
		name := libraryName()
		if name == "" {
			t.Skip("no guard library on this platform")
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fake"), 0o644); err != nil {
			t.Fatal(err)
		}
		sum := fmt.Sprintf("%x", sha256.Sum256([]byte("fake")))
		prevPin, hadPin := pinnedHashes[name]
		pinnedHashes[name] = sum
		t.Cleanup(func() {
			if hadPin {
				pinnedHashes[name] = prevPin
			} else {
				delete(pinnedHashes, name)
			}
		})
	}
	return dir
}

func TestPreloadEnvNoLibrary(t *testing.T) {
	withFakeLib(t, false)
	if got := PreloadEnv(map[string]string{"A": "supersecret"}); got != nil {
		t.Errorf("expected nil when no guard library is installed, got %v", got)
	}
}

func TestPreloadEnvSetsMaskAndPreload(t *testing.T) {
	withFakeLib(t, true)
	got := PreloadEnv(map[string]string{"A": "supersecret", "B": "othersecret"})
	if len(got) != 2 {
		t.Fatalf("expected 2 env entries, got %d: %v", len(got), got)
	}
	var mask, preload string
	for _, e := range got {
		if strings.HasPrefix(e, MaskEnvKey+"=") {
			mask = strings.TrimPrefix(e, MaskEnvKey+"=")
		}
		if strings.HasPrefix(e, preloadKey()+"=") {
			preload = strings.TrimPrefix(e, preloadKey()+"=")
		}
	}
	if preload == "" {
		t.Errorf("expected %s to be set, got %v", preloadKey(), got)
	}
	if mask == "" {
		t.Fatalf("expected %s to be set, got %v", MaskEnvKey, got)
	}
	for _, want := range []string{"supersecret", "othersecret"} {
		if !strings.Contains(mask, want) {
			t.Errorf("mask %q missing %q", mask, want)
		}
	}
}

func TestPreloadEnvSkipsShortValues(t *testing.T) {
	withFakeLib(t, true)
	if got := PreloadEnv(map[string]string{"A": "abc"}); got != nil {
		t.Errorf("values shorter than 4 chars must not be masked, got %v", got)
	}
}

func TestEnvKeysIncludesBothVariables(t *testing.T) {
	keys := EnvKeys()
	if len(keys) == 0 || keys[0] != MaskEnvKey {
		t.Errorf("EnvKeys must include %s first, got %v", MaskEnvKey, keys)
	}
	if preloadKey() != "" && (len(keys) < 2 || keys[1] != preloadKey()) {
		t.Errorf("EnvKeys must include %s, got %v", preloadKey(), keys)
	}
}

func TestLocateRefusesTamperedBytes(t *testing.T) {
	dir := withFakeLib(t, true)
	name := libraryName()
	if name == "" {
		t.Skip("no guard library on this platform")
	}
	// Rewrite the file after pinning: hash mismatch must refuse.
	if err := os.WriteFile(filepath.Join(dir, name), []byte("evil"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Locate(); got != "" {
		t.Errorf("tampered library must be refused, got %q", got)
	}
}

func TestLocateRefusesWorldWritable(t *testing.T) {
	dir := withFakeLib(t, true)
	name := libraryName()
	if name == "" {
		t.Skip("no guard library on this platform")
	}
	p := filepath.Join(dir, name)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// chmod (not WriteFile mode) defeats umask: the file must REALLY be 666.
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	_ = raw
	if got := Locate(); got != "" {
		t.Errorf("world-writable library must be refused, got %q", got)
	}
}

func TestPreloadEnvSkipsSeparatorValues(t *testing.T) {
	withFakeLib(t, true)
	got := PreloadEnv(map[string]string{"A": "goodsecret", "B": "frag\x1fment"})
	if got == nil {
		t.Fatal("expected entries for the good value")
	}
	for _, e := range got {
		if strings.Contains(e, "frag") {
			t.Errorf("separator-fragmented value must not enter the mask: %v", got)
		}
	}
}

func TestUnmaskable(t *testing.T) {
	short, frag := Unmaskable(map[string]string{
		"PIN":  "123",
		"TOK":  "ab\x1fcd",
		"GOOD": "goodsecret",
	})
	if len(short) != 1 || short[0] != "PIN" {
		t.Errorf("short = %v, want [PIN]", short)
	}
	if len(frag) != 1 || frag[0] != "TOK" {
		t.Errorf("fragmented = %v, want [TOK]", frag)
	}
}
