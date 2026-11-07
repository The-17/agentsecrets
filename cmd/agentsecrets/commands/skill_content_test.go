package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot walks up from this file's directory until it finds go.mod. It is the
// anchor for the guard references in codeGatedGuarantees, which are relative to
// the repository root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate repo root (go.mod) from %s", dir)
	return ""
}

// TestSkillGuaranteesResolveToRealFiles is the F5 safeguard. Each claim in
// codeGatedGuarantees is pinned to a file that proves it. If a guard file is
// renamed or deleted, the prompt would over-claim, so this test fails instead.
func TestSkillGuaranteesResolveToRealFiles(t *testing.T) {
	root := repoRoot(t)
	for _, g := range codeGatedGuarantees {
		target := g.guard
		symbol := ""
		if idx := strings.IndexByte(g.guard, ':'); idx >= 0 {
			target = g.guard[:idx]
			symbol = g.guard[idx+1:]
		}
		path := filepath.Join(root, target)
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("guard %q references %q which does not exist: %v", g.claim, target, err)
		}
		if symbol != "" && !strings.Contains(string(contents), symbol) {
			t.Fatalf("guard %q references symbol %q not found in %q", g.claim, symbol, target)
		}
	}
}

// TestSkillBodyContainsGuaranteeSection proves the generated block actually
// reaches both surface outputs.
func TestSkillBodyContainsGuaranteeSection(t *testing.T) {
	for _, got := range []string{WorkflowSkill(), InstalledSkill()} {
		if !strings.Contains(got, "WHAT THE ENGINE ENFORCES IN CODE") {
			t.Errorf("skill output missing generated guarantee section")
		}
		for _, g := range codeGatedGuarantees {
			if !strings.Contains(got, g.guard) {
				t.Errorf("skill output missing guard reference %q", g.guard)
			}
		}
	}
}
