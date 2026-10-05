// Package envguard locates and configures the preload interposer that
// `agentsecrets env` attaches to the child process it spawns.
//
// The interposer marks the child non-dumpable (so no other process running as the
// same user can read its environment) and redacts secret values from what the
// child prints. The redaction is best-effort hygiene, not a security boundary.
package envguard

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MaskSeparator joins secret values in the mask variable. Values containing
// it are excluded from the mask (see Unmaskable) since they would fragment
// at parse time and match nothing.
const MaskSeparator = "\x1f"

// MaskEnvKey is the variable the interposer reads to learn what to redact.
const MaskEnvKey = "AGENTSECRETS_MASK"

// searchDirsHook is overridden in tests to redirect library discovery.
var searchDirsHook = searchDirs

// pinnedHashes maps interposer filename -> expected sha256 hex. Populated by
// hashes_generated.go (written by `make envguard` alongside the library).
// Absent file = empty map = no library ever verifies (fail closed).
var pinnedHashes = map[string]string{}

// Locate returns the path to the guard library for this platform, or "" when
// none is installed or none verifies. Verification is threefold, and every
// failure mode returns "" (guard absent — the child runs with parent-side
// masking only, and the caller warns):
//
//  1. Exactly one search location: the directory holding the agentsecrets
//     binary. User-writable sidecar directories are NOT searched — a
//     preload path an attacker can write to is remote code execution in
//     every future child.
//  2. The library bytes must hash to the pin recorded at build time
//     (hashes_generated.go, written by `make envguard` alongside the
//     library). A library built by any other route has no pin and is
//     refused. TOCTOU between verify and exec is accepted: an attacker who
//     can rewrite the binary directory between our stat and the child's
//     exec already owns this user account outright.
//  3. The library must be owned by our own uid and not world-writable
//     (multi-user machines, sloppy installs).
func Locate() string {
	name := libraryName()
	if name == "" {
		return ""
	}
	for _, dir := range searchDirsHook() {
		p := filepath.Join(dir, name)
		if verifiedLibrary(p) {
			return p
		}
	}
	return ""
}

// verifiedLibrary reports whether p is a pinned, sanely-owned guard library.
func verifiedLibrary(p string) bool {
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() {
		return false
	}
	if st, ok := fileOwner(fi); ok {
		if st.uid != os.Getuid() || fi.Mode().Perm()&0o002 != 0 {
			return false
		}
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(raw))
	want, ok := pinnedHashes[filepath.Base(p)]
	return ok && subtleEqual(sum, want)
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func searchDirs() []string {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	return dirs
}

// Unmaskable reports secret KEYS whose values cannot be redacted, so the
// caller can warn by name (never by value):
//   - values shorter than 4 bytes would redact unrelated text everywhere,
//     so every redactor (parent writer, C interposer) skips them;
//   - values containing the unit separator would fragment at parse time and
//     match nothing, so they are excluded from the mask outright.
//
// Either way the value is still INJECTED (the child needs it) but never
// redacted: the caller must say so loudly.
func Unmaskable(secrets map[string]string) (short, fragmented []string) {
	for k, v := range secrets {
		switch {
		case len(v) < 4:
			short = append(short, k)
		case strings.Contains(v, MaskSeparator):
			fragmented = append(fragmented, k)
		}
	}
	return short, fragmented
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
		if len(v) >= 4 && !strings.Contains(v, MaskSeparator) {
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
