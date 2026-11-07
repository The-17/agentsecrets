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

// TestOpenClawSkillMatchesVendoredFile pins the OpenClaw registry copy
// (integrations/openclaw/SKILL.md) to the generator. It used to be a hand-edited
// spin that fell out of sync with the universal skill (it still carried the old
// "THE RULES" block). This guard fails if anyone edits that file without
// regenerating it with `agentsecrets skill --openclaw`.
func TestOpenClawSkillMatchesVendoredFile(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "integrations", "openclaw", "SKILL.md")
	want := OpenClawSkill()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read vendored OpenClaw skill %s: %v", path, err)
	}
	if string(got) != want {
		t.Errorf("integrations/openclaw/SKILL.md differs from OpenClawSkill(); regenerate with `agentsecrets skill --openclaw > %s`", path)
	}
	// The OpenClaw body must be the same single source as every other surface.
	if !strings.Contains(OpenClawSkill(), skillBodyExpanded()) {
		t.Error("OpenClawSkill body does not contain the shared skill body")
	}
	if !strings.Contains(OpenClawSkill(), "THE EXEC PROVIDER") {
		t.Error("OpenClawSkill is missing the exec-provider appendix")
	}
}
