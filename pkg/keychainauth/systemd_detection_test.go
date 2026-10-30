package keychainauth

import (
	"os"
	"runtime"
	"testing"
)

// TestIsSystemdBooted verifies that isSystemdBooted uses the sd_booted(3)
// sentinel (/run/systemd/system) and is not fooled by a unit file on disk.
func TestIsSystemdBooted(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("systemd detection is Linux-only")
	}

	tmp := t.TempDir()
	orig := systemdRuntimeDir
	t.Cleanup(func() { systemdRuntimeDir = orig })

	// No directory at the path → not booted.
	systemdRuntimeDir = tmp + "/run/systemd/system"
	if isSystemdBooted() {
		t.Error("isSystemdBooted() = true, want false when sentinel dir is absent")
	}

	// Directory present → booted.
	if err := os.MkdirAll(systemdRuntimeDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if !isSystemdBooted() {
		t.Error("isSystemdBooted() = false, want true when sentinel dir exists")
	}

	// A regular file at the path is not a directory → not booted.
	if err := os.MkdirAll(tmp+"/run/systemd", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	fileOnly := tmp + "/run/systemd/file-not-dir"
	if err := os.WriteFile(fileOnly, nil, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	systemdRuntimeDir = fileOnly
	if isSystemdBooted() {
		t.Error("isSystemdBooted() = true, want false when path is a file not a directory")
	}
}

// TestSystemdUnitExistsRequiresBootedSystemd is the regression test for the
// WSL / Docker / LXC bug: systemdUnitExists must return false when a .service
// file exists on disk but systemd is not the running init. Previously this
// caused agentsecrets to call `sudo systemctl restart keychain-auth` on any
// Linux host that had ever run `keychain-auth install`, breaking non-systemd
// setups with an unactionable "System has not been booted with systemd" error.
func TestSystemdUnitExistsRequiresBootedSystemd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("unit-file detection is Linux-only")
	}

	tmp := t.TempDir()

	origRuntime := systemdRuntimeDir
	origPaths := systemdUnitSearchPaths
	t.Cleanup(func() {
		systemdRuntimeDir = origRuntime
		systemdUnitSearchPaths = origPaths
	})

	// Create a fake unit file.
	if err := os.MkdirAll(tmp+"/etc/systemd/system", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	unitPath := tmp + "/etc/systemd/system/keychain-auth.service"
	if err := os.WriteFile(unitPath, []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	systemdUnitSearchPaths = []string{unitPath}

	// Unit file present but systemd NOT booted (WSL/Docker/LXC scenario).
	systemdRuntimeDir = tmp + "/run/systemd/system"
	if systemdUnitExists() {
		t.Error("systemdUnitExists() = true, want false: unit file present but systemd not booted")
	}

	// systemd now booted: create sentinel dir.
	if err := os.MkdirAll(systemdRuntimeDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if !systemdUnitExists() {
		t.Error("systemdUnitExists() = false, want true: unit file present AND systemd is booted")
	}

	// Unit file absent even when systemd is booted → false.
	systemdUnitSearchPaths = []string{tmp + "/nonexistent/keychain-auth.service"}
	if systemdUnitExists() {
		t.Error("systemdUnitExists() = true, want false: systemd booted but no unit file")
	}
}
