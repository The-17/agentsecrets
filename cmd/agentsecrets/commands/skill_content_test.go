package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The skill is generated text next to a real binary. The moment it teaches a
// command or flag that does not exist, an agent following it learns to distrust
// everything else it says. These tests walk the actual cobra tree, so a renamed
// or removed command fails here rather than in a user's terminal.
//
// Add a command to the skill, add it here.

// findCmd resolves a path like ["agent","token","rotate"] against rootCmd.
func findCmd(t *testing.T, path ...string) *cobra.Command {
	t.Helper()
	cmd, _, err := rootCmd.Find(path)
	if err != nil || cmd == nil {
		t.Fatalf("skill teaches `agentsecrets %s` but no such command exists: %v",
			strings.Join(path, " "), err)
	}
	if cmd.Name() != path[len(path)-1] {
		t.Fatalf("`agentsecrets %s` resolved to %q, not %q",
			strings.Join(path, " "), cmd.Name(), path[len(path)-1])
	}
	return cmd
}

// requireFlag proves a flag the skill teaches exists on the command that takes it.
// pflag's Lookup takes the bare name, so the dashes the skill writes are trimmed.
func requireFlag(t *testing.T, flag string, path ...string) {
	t.Helper()
	name := strings.TrimLeft(flag, "-")
	cmd := findCmd(t, path...)
	if cmd.Flags().Lookup(name) == nil && cmd.PersistentFlags().Lookup(name) == nil {
		t.Errorf("skill teaches `agentsecrets %s %s` but that flag does not exist",
			strings.Join(path, " "), flag)
	}
}

// TestSkillCommandsExist proves every command the skill references is real by
// parsing them out of the generated text, not from a hand-kept list. A list
// would drift exactly like the skill did.
func TestSkillCommandsExist(t *testing.T) {
	bodies := map[string]string{"SKILL.md": expand(skillBody)}
	for name, body := range SkillReferences() {
		bodies[name] = body
	}
	for name, body := range bodies {
		for _, ref := range extractSkillCommands(body) {
			path := strings.Fields(ref)
			if !resolves(path) {
				t.Errorf("%s teaches `agentsecrets %s`, which is not a command", name, ref)
			}
		}
	}
}

// extractSkillCommands pulls command paths out of code, not prose. Scanning
// free text catches "agentsecrets status reports ..." and calls "reports" a
// subcommand. Skills put runnable commands in fenced blocks or inline code, so
// only those are checked; prose mentions are allowed to be prose.
func extractSkillCommands(body string) []string {
	var out []string
	seen := map[string]bool{}

	add := func(snippet string) {
		idx := strings.Index(snippet, "agentsecrets ")
		if idx < 0 {
			return
		}
		rest := snippet[idx+len("agentsecrets "):]
		var words []string
		for _, w := range strings.Fields(rest) {
			w = strings.Trim(w, "`'\",;()[]")
			if w == "" || strings.HasPrefix(w, "-") || strings.HasPrefix(w, "<") || strings.HasPrefix(w, "$") || strings.HasPrefix(w, "#") {
				break
			}
			if w != strings.ToLower(w) || strings.ContainsAny(w, "_/.|") {
				break
			}
			// A hyphen inside a word marks an argument (my-app, bot-name), not
			// a subcommand. Subcommand names never contain a hyphen here, so
			// treat one as the end of the command path.
			if strings.Contains(w, "-") {
				break
			}
			words = append(words, w)
			if len(words) == 4 {
				break
			}
		}
		if len(words) == 0 {
			return
		}
		ref := strings.Join(words, " ")
		if !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
	}

	inFence := false
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			add(line)
			continue
		}
		// Outside a fence: only inline-code spans are commands.
		for _, part := range strings.Split(line, "`") {
			if strings.Contains(part, "agentsecrets ") {
				add(part)
			}
		}
	}
	return out
}

// resolves reports whether path names a real command. It walks as deep as the
// cobra tree allows, then decides:
//   - every word matched a command: real.
//   - words remain and the matched command takes positional arguments (it has
//     no subcommands of its own): real, the extras are arguments
//     (`mode cloud`).
//   - words remain and the command HAS subcommands: the extra word is a typo
//     (`secrets rotation stats`), which is exactly the class this guards.
func resolves(path []string) bool {
	cur := rootCmd
	consumed := 0
	for _, w := range path {
		var next *cobra.Command
		for _, c := range cur.Commands() {
			if c.Name() == w || c.HasAlias(w) {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		cur = next
		consumed++
	}
	if consumed == 0 {
		return false
	}
	if consumed == len(path) {
		return true
	}
	return len(cur.Commands()) == 0
}

// TestSkillFlagsExist proves the flags the skill teaches are real.
func TestSkillFlagsExist(t *testing.T) {
	for _, f := range []string{"--generate", "--stdin", "--from-command"} {
		requireFlag(t, f, "secrets", "set")
	}
	requireFlag(t, "--remote", "secrets", "list")

	for _, f := range []string{"--bearer", "--header", "--body", "--url", "--method", "--cloud", "--local", "--basic", "--query", "--form-field"} {
		requireFlag(t, f, "call")
	}
	// `env` parses its own flags in RunE (everything after `--` belongs to the
	// child), so cobra holds none. Its flag contract lives in Use/Long, which is
	// also what `--help` prints; assert against that instead of a FlagSet.
	envCmd := findCmd(t, "env")
	envHelp := envCmd.Use + "\n" + envCmd.Long
	for _, f := range []string{"--only", "--env", "--cloud", "--sandbox", "--local"} {
		if !strings.Contains(envHelp, f) {
			t.Errorf("skill teaches `agentsecrets env %s` but the command's own usage does not document it", f)
		}
	}
	for _, f := range []string{"--credential", "--since", "--blocked", "--failed"} {
		requireFlag(t, f, "logs")
	}
	requireFlag(t, "--check-only", "doctor")
}

// TestSkillNeverTeachesPhantomTokenRotationStatus pins the fix for the one
// phantom reference that shipped: `agent token rotation status` never existed;
// the token view is `agent token list`.
func TestSkillNeverTeachesPhantomTokenRotationStatus(t *testing.T) {
	body := expand(skillBody)
	if strings.Contains(body, "agent token rotation status") {
		t.Error("skill teaches `agent token rotation status`, which is not a command; the token view is `agent token list`")
	}
}

// TestSkillReferencesShipWithTheSkill proves the three reference files exist and
// are non-trivial. The features contract promises them alongside SKILL.md.
func TestSkillReferencesShipWithTheSkill(t *testing.T) {
	refs := SkillReferences()
	for _, name := range []string{"lifecycle.md", "runtimes.md", "recovery.md"} {
		body, ok := refs[name]
		if !ok {
			t.Errorf("missing reference file %s", name)
			continue
		}
		if len(body) < 600 {
			t.Errorf("reference %s is too thin (%d bytes) to be useful", name, len(body))
		}
		if strings.Contains(body, "__FENCE__") || strings.Contains(body, "__B__") {
			t.Errorf("reference %s still contains generator placeholders", name)
		}
	}
}

// TestVendoredOpenClawSkillMatchesSource proves the copy published to the
// OpenClaw registry is the same body as the generated skill. A vendored copy
// is exactly the thing that drifts, so it is asserted rather than trusted.
func TestVendoredOpenClawSkillMatchesSource(t *testing.T) {
	path := filepath.Join("..", "..", "..", "integrations", "openclaw", "SKILL.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("vendored OpenClaw skill missing: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, expand(skillBody)) {
		t.Error("integrations/openclaw/SKILL.md body differs from the generated skill; regenerate it from skill_content.go")
	}
	if strings.Contains(body, "autonomously") || strings.Contains(body, "KEY_NAME=value") {
		t.Error("vendored OpenClaw skill still teaches the removed v3 behaviour")
	}
}

// TestSkillCommandExportsEveryClient proves the universal export writes the
// same package the native installers do. This is the path for every agent we
// do not ship an installer for, so it must produce identical bytes.
func TestSkillCommandExportsEveryClient(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "skills", "agentsecrets")
	if err := writeSkillPackage(dir); err != nil {
		t.Fatalf("writeSkillPackage: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(dir, "SKILL.md"))
	if err != nil {
		t.Fatalf("SKILL.md not written: %v", err)
	}
	if string(body) != InstalledSkill() {
		t.Error("exported SKILL.md differs from the installed skill")
	}

	refs := SkillReferences()
	if len(refs) == 0 {
		t.Fatal("no references generated")
	}
	for name := range refs {
		if _, err := os.Stat(filepath.Join(dir, "references", name)); err != nil {
			t.Errorf("references/%s not written: %v", name, err)
		}
	}

	// The printed form must be the same bytes, so `agentsecrets skill > file`
	// is equivalent to --dir for the body.
	if got := sortedReferenceNames(); len(got) != len(refs) {
		t.Errorf("sortedReferenceNames returned %d names, want %d", len(got), len(refs))
	}
}

// TestSkillCommandIsRegistered proves the escape hatch exists on the CLI.
func TestSkillCommandIsRegistered(t *testing.T) {
	cmd := findCmd(t, "skill")
	for _, flag := range []string{"all", "version", "dir"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("agentsecrets skill is missing --%s", flag)
		}
	}
}

// TestSkillReferencesTeachRealCommands proves the references do not invent
// commands either. Same rule as the body: every documented verb must exist.
func TestSkillReferencesTeachRealCommands(t *testing.T) {
	refs := SkillReferences()
	for name, body := range refs {
		for _, phantom := range []string{
			"agentsecrets secret ",       // singular does not exist
			"agentsecrets workspace use", // it is `workspace switch`
			"agentsecrets agent token rotation status",
			"agentsecrets allowlist ", // it is `workspace allowlist`
		} {
			if strings.Contains(body, phantom) {
				t.Errorf("%s teaches %q, which is not a command", name, phantom)
			}
		}
	}
}
