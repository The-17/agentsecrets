package envguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withFakeLib points discovery at a temp dir containing (or not containing) a
// fake guard library, restoring the real search afterwards.
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
