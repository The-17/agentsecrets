package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInitWritesSkillAndReferences proves `init` and `mcp install` ship the
// same skill package: the workflow file plus references/ beside it, from the
// one generated source.
func TestInitWritesSkillAndReferences(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	if err := writeWorkflowFile(); err != nil {
		t.Fatalf("writeWorkflowFile: %v", err)
	}

	wf := filepath.Join(dir, ".agent", "workflows", "agentsecrets.md")
	body, err := os.ReadFile(wf)
	if err != nil {
		t.Fatalf("workflow not written: %v", err)
	}
	if strings.TrimSpace(string(body)) != strings.TrimSpace(workflowContentTemplate) {
		t.Error("workflow file differs from the shared template")
	}

	for name := range SkillReferences() {
		p := filepath.Join(dir, ".agent", "workflows", "agentsecrets", name)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("init did not write references/%s: %v", name, err)
		}
	}
}
