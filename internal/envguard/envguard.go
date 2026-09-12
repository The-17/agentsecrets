// Package envguard locates and configures the preload interposer that
// `agentsecrets env` attaches to the child process it spawns.
//
// The interposer marks the child non-dumpable (so no other process running as the
// same user can read its environment) and redacts secret values from what the
// child prints. The redaction is best-effort hygiene, not a security boundary.
package envguard

import (
	"os"
	"path/filepath"
	"strings"
)

// MaskSeparator joins secret values in the mask variable. It is the ASCII Unit
// Separator, which cannot occur in an ordinary secret value.
const MaskSeparator = "\x1f"

// MaskEnvKey is the variable the interposer reads to learn what to redact.
const MaskEnvKey = "AGENTSECRETS_MASK"

// searchDirsHook is overridden in tests to redirect library discovery.
var searchDirsHook = searchDirs

// Locate returns the path to the guard library for this platform, or "" when none
// is installed. The library is built by `make envguard` and shipped next to the
// agentsecrets binary.
func Locate() string {
	name := libraryName()
	if name == "" {
		return ""
	}
	for _, dir := range searchDirsHook() {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

func searchDirs() []string {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".agentsecrets", "bin"))
	}
	return dirs
}

// PreloadEnv returns the environment entries that activate the guard for a child
// process, or nil when no guard applies to this platform (the child then runs
// exactly as before, unprotected).
func PreloadEnv(secrets map[string]string) []string {
	lib := Locate()
	if lib == "" {
		return nil
	}
	values := make([]string, 0, len(secrets))
	for _, v := range secrets {
		if len(v) >= 4 { // very short values would redact unrelated text
			values = append(values, v)
		}
	}
	if len(values) == 0 {
		return nil
	}
	return []string{
		MaskEnvKey + "=" + strings.Join(values, MaskSeparator),
		preloadKey() + "=" + lib,
	}
}

// EnvKeys returns the variable names PreloadEnv may set, so callers can strip any
// inherited copies before appending: duplicate entries in the environment are
// ambiguous to the dynamic loader.
func EnvKeys() []string {
	keys := []string{MaskEnvKey}
	if k := preloadKey(); k != "" {
		keys = append(keys, k)
	}
	return keys
}
