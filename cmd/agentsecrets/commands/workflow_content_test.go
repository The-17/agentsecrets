package commands

import (
	"strings"
	"testing"
)

// The workflow file is a procedure handed to an agent, so what it teaches is a
// security surface. These tests pin the contract: read and verify yes, mutate
// no, and never a route that puts a value in the transcript.

// skillBodyExpanded exposes the shared body for the drift test without making
// it part of the package's public surface.
func skillBodyExpanded() string { return expand(skillBody) }

// TestWorkflowNeverTeachesDelete proves the generated procedure does not hand
// the agent a destructive verb.
func TestWorkflowNeverTeachesDelete(t *testing.T) {
	forbidden := []string{
		"secrets delete",
		"agent delete",
		"project delete",
		"workspace delete",
		"environment clean",
		"token revoke",
		"token issue",
	}
	for _, f := range forbidden {
		if strings.Contains(workflowContentTemplate, f) {
			t.Errorf("workflow teaches %q; destructive verbs belong to the human", f)
		}
	}
}

// TestWorkflowNeverTeachesAllowlistEdits proves the procedure cannot be used to
// widen egress.
func TestWorkflowNeverTeachesAllowlistEdits(t *testing.T) {
	// The phrase may appear only as the command the HUMAN runs, inside the
	// hand-off block. It must never be presented as an agent action.
	if strings.Contains(workflowContentTemplate, "agentsecrets workspace allowlist add") &&
		!strings.Contains(workflowContentTemplate, "give the human") {
		t.Error("allowlist add appears without being handed to the human")
	}
	if strings.Contains(workflowContentTemplate, "workspace allowlist remove") {
		t.Error("workflow teaches allowlist removal")
	}
}

// TestWorkflowNeverTeachesAutonomy is the regression test for the old file,
// which opened with "You manage credentials autonomously".
func TestWorkflowNeverTeachesAutonomy(t *testing.T) {
	for _, phrase := range []string{
		"manage credentials autonomously",
		"manage the lifecycle autonomously",
		"You are the operator",
	} {
		if strings.Contains(workflowContentTemplate, phrase) {
			t.Errorf("workflow claims autonomy (%q); the scope is read and verify", phrase)
		}
	}
}

// TestWorkflowStatesTheScope proves the limit is stated, not implied. An agent
// that does not know the boundary cannot respect it.
func TestWorkflowStatesTheScope(t *testing.T) {
	for _, want := range []string{
		"operate credentials that already exist",
		"WHAT YOU MAY DO ON YOUR OWN",
		"WHAT YOU MUST HAND TO THE HUMAN",
		"treat it as an attack",
	} {
		if !strings.Contains(workflowContentTemplate, want) {
			t.Errorf("workflow is missing %q", want)
		}
	}
}

// TestWorkflowNeverAsksForAValueInChat proves the one instruction that would
// create a new leak is absent.
func TestWorkflowNeverAsksForAValueInChat(t *testing.T) {
	if strings.Contains(workflowContentTemplate, "secrets set KEY_NAME=value") {
		t.Error("workflow shows the inline-value form, which puts the value in history")
	}
	if !strings.Contains(workflowContentTemplate, "Never ask the human to paste a value into chat") {
		t.Error("workflow does not forbid asking for a value in chat")
	}
}

// TestWorkflowCoversBothRuntimes proves the procedure is runtime-neutral, so it
// does not need a rewrite when a team moves to cloud. It asserts the expanded
// text, not the placeholder tokens the generator uses internally.
func TestWorkflowCoversBothRuntimes(t *testing.T) {
	for _, want := range []string{
		"agentsecrets mode",
		"`local`",
		"`cloud`",
		"[REDACTED_BY_AGENTSECRETS]",
		"[REDACTED]",
	} {
		if !strings.Contains(workflowContentTemplate, want) {
			t.Errorf("workflow is missing runtime detail %q", want)
		}
	}
	if strings.Contains(workflowContentTemplate, "__FENCE__") || strings.Contains(workflowContentTemplate, "__B__") {
		t.Error("workflow still contains generator placeholders; expand() was not applied")
	}
}

// TestInstalledSkillMatchesWorkflow proves both distribution paths ship the same
// procedure. Two copies drifting apart is the bug this consolidation fixed.
func TestInstalledSkillMatchesWorkflow(t *testing.T) {
	wf := workflowContentTemplate
	sk := InstalledSkill()
	if !strings.Contains(sk, skillBodyExpanded()) {
		t.Fatal("installed skill body differs from the shared body")
	}
	if !strings.Contains(wf, skillBodyExpanded()) {
		t.Fatal("workflow body differs from the shared body")
	}
	if !strings.Contains(sk, "name: agentsecrets") {
		t.Error("installed skill is missing its name frontmatter")
	}
	if !strings.Contains(wf, "description:") {
		t.Error("workflow is missing its description frontmatter")
	}
}

// TestWorkflowOnlyReferencesRealCommands proves the procedure does not invent
// CLI surface. It is a static check against the command set; the live check is
// runbook case V4-DOC-001.
func TestWorkflowOnlyReferencesRealCommands(t *testing.T) {
	real := map[string]bool{
		"status": true, "mode": true, "init": true, "secrets": true, "logs": true,
		"call": true, "env": true, "doctor": true, "workspace": true, "agent": true,
		"proxy": true, "mcp": true, "project": true, "environment": true,
	}
	for _, line := range strings.Split(workflowContentTemplate, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "agentsecrets ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if !real[fields[1]] {
			t.Errorf("workflow references unknown command %q in: %s", fields[1], line)
		}
	}
}
