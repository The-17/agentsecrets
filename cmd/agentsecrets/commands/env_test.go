package commands

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSandboxArgv(t *testing.T) {
	got, err := sandboxArgv([]string{"echo", "hi"})

	if runtime.GOOS != "linux" {
		if err == nil {
			t.Fatal("expected --sandbox to be unsupported off Linux")
		}
		return
	}
	if _, lookErr := exec.LookPath("unshare"); lookErr != nil {
		if err == nil {
			t.Fatal("expected an error when unshare is unavailable")
		}
		return
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filepath.Base(got[0]) != "unshare" {
		t.Errorf("expected argv[0] to be unshare, got %q", got[0])
	}
	joined := strings.Join(got, " ")
	for _, want := range []string{"--net", "--user", "echo hi"} {
		if !strings.Contains(joined, want) {
			t.Errorf("sandbox argv %q missing %q", joined, want)
		}
	}
}

func TestStripEnvRemovesNamedKeys(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"LD_PRELOAD=/some/other.so",
		"AGENTSECRETS_MASK=stale",
		"HOME=/home/x",
	}
	got := stripEnv(env, []string{"LD_PRELOAD", "AGENTSECRETS_MASK"})

	for _, e := range got {
		if strings.HasPrefix(e, "LD_PRELOAD=") || strings.HasPrefix(e, "AGENTSECRETS_MASK=") {
			t.Errorf("expected %q to be stripped, got %v", e, got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 surviving entries, got %v", got)
	}
	if got[0] != "PATH=/usr/bin" || got[1] != "HOME=/home/x" {
		t.Errorf("unexpected surviving entries: %v", got)
	}
}

func TestStripEnvKeepsUnrelatedAndHandlesNoEquals(t *testing.T) {
	env := []string{"KEEP=1", "MALFORMED", "DROP=2"}
	got := stripEnv(env, []string{"DROP"})
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %v", got)
	}
	for _, e := range got {
		if e == "DROP=2" {
			t.Errorf("DROP should have been stripped, got %v", got)
		}
	}
}
