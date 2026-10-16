package commands

import (
	"bytes"
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

func TestStripEnvRemovesInheritedSecretKeys(t *testing.T) {
	// An attacker-planted parent value must not survive next to the keychain
	// value: duplicates are ambiguous to the loader (first match wins).
	env := []string{"PATH=/usr/bin", "DATABASE_URL=postgres://evil/x", "OTHER=1"}
	got := stripEnv(env, []string{"DATABASE_URL"})
	for _, e := range got {
		if strings.HasPrefix(e, "DATABASE_URL=") {
			t.Errorf("inherited secret key must be stripped, got %v", got)
		}
	}
	if len(got) != 2 {
		t.Errorf("expected 2 surviving entries, got %v", got)
	}
}

func TestScrubArgv(t *testing.T) {
	secrets := map[string]string{"TOKEN": "sk_live_abc123", "OTHER": "xyz"}
	got := scrubArgv([]string{"deploy", "--token=sk_live_abc123", "--env", "prod"}, secrets)
	if got[1] != "[REDACTED]" {
		t.Errorf("argv value not scrubbed: %v", got)
	}
	if got[0] != "deploy" || got[3] != "prod" {
		t.Errorf("innocent argv mangled: %v", got)
	}
	// Short values are skipped (false-positive rule, same as every masker).
	got = scrubArgv([]string{"run", "xyz"}, map[string]string{"A": "xyz"})
	if got[1] != "xyz" {
		t.Errorf("short value must not be scrubbed: %v", got)
	}
}

func containsExact(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func TestGenerateVariantsSkipsUbiquitousLiteralsVerbatim(t *testing.T) {
	got := generateVariants(map[string]string{
		"POLAR_SANDBOX": "true",
		"API_KEY":       "sk_live_abc123",
	})
	// A boolean secret must not be masked in its literal form: doing so turns
	// every unrelated "true" in the child's output into [REDACTED].
	for _, v := range got {
		if strings.EqualFold(v, "true") {
			t.Errorf("boolean literal %q must not be masked verbatim; got %v", v, got)
		}
	}
	// Its encoded forms are distinctive, so they are still masked.
	if !containsExact(got, "dHJ1ZQ==") {
		t.Errorf("base64 of the boolean should still be masked: %v", got)
	}
	// A distinctive secret is still masked verbatim.
	if !containsExact(got, "sk_live_abc123") {
		t.Errorf("a distinctive secret must be masked verbatim: %v", got)
	}
}

func TestMaskingWriterLeavesUbiquitousLiteralsAlone(t *testing.T) {
	var buf bytes.Buffer
	mw := &MaskingWriter{
		underlying: &buf,
		secrets: generateVariants(map[string]string{
			"POLAR_SANDBOX": "true",
			"TOKEN":         "sk_live_abc123",
		}),
	}
	if _, err := mw.Write([]byte("enabled=true token=sk_live_abc123\n")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Flush(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "enabled=true") {
		t.Errorf("unrelated boolean output was mangled: %q", out)
	}
	if strings.Contains(out, "sk_live_abc123") {
		t.Errorf("secret leaked through the masker: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("expected the secret to be redacted: %q", out)
	}
}
