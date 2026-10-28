package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/ui"
)

// The skill command is the escape hatch for every agent we do not ship an
// installer for. `mcp install` writes the skill into the clients we know
// (Claude Code, Codex, OpenClaw) and configures the MCP clients (Claude
// Desktop, Cursor). This command hands the same bytes to anyone else: print it
// and pipe it wherever that agent reads instructions, or point --dir at that
// agent's skills folder.
//
// It is also the source of truth for the copies vendored in docs and in the
// OpenClaw registry, which a drift test pins to the same generator.

var skillCmd = &cobra.Command{
	Use:   "skill",
	Short: "Print or install the AgentSecrets agent skill",
	Long: `Print or install the standard AgentSecrets skill.

The skill teaches an agent to operate credentials by key name without ever
seeing a value: read, diff, sync, audit, verify, and hand every irreversible
action back to the human.

Print it (works for any agent that reads a markdown instruction file):

  agentsecrets skill                    # SKILL.md to stdout
  agentsecrets skill --all              # SKILL.md plus the reference files
  agentsecrets skill --version          # just the version string

Write it into an agent's skills directory:

  agentsecrets skill --dir ~/.windsurf/skills/agentsecrets
  agentsecrets skill --dir ./.agent/skills/agentsecrets

For the clients we install natively, use "agentsecrets mcp install" instead.`,
	Args: cobra.NoArgs,
	RunE: runSkill,
}

func init() {
	skillCmd.Flags().Bool("all", false, "print SKILL.md and every reference file, separated by headers")
	skillCmd.Flags().Bool("version", false, "print only the skill version")
	skillCmd.Flags().String("dir", "", "write SKILL.md and references/ into this directory instead of printing")
}

func runSkill(cmd *cobra.Command, args []string) error {
	showVersion, _ := cmd.Flags().GetBool("version")
	showAll, _ := cmd.Flags().GetBool("all")
	dir, _ := cmd.Flags().GetString("dir")

	if showVersion {
		fmt.Println(skillVersion)
		return nil
	}

	if dir != "" {
		return writeSkillPackage(dir)
	}

	fmt.Print(InstalledSkill())
	if showAll {
		for _, name := range sortedReferenceNames() {
			fmt.Printf("\n--- references/%s ---\n\n", name)
			fmt.Print(SkillReferences()[name])
		}
	}
	return nil
}

// writeSkillPackage writes SKILL.md and references/ into dir, creating it if
// needed. Same layout the native installers use, so any client that reads a
// skills directory works.
func writeSkillPackage(dir string) error {
	refDir := filepath.Join(dir, "references")
	if err := os.MkdirAll(refDir, 0755); err != nil {
		return fmt.Errorf("could not create %s: %w", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(InstalledSkill()), 0644); err != nil {
		return fmt.Errorf("failed to write SKILL.md: %w", err)
	}
	for name, body := range SkillReferences() {
		if err := os.WriteFile(filepath.Join(refDir, name), []byte(body), 0644); err != nil {
			return fmt.Errorf("failed to write references/%s: %w", name, err)
		}
	}
	ui.Success(fmt.Sprintf("Installed the AgentSecrets skill into %s", dir))
	ui.Info("Point your agent at SKILL.md, or at the directory if it reads a skills folder.")
	return nil
}

// sortedReferenceNames gives a stable order for --all output and tests.
func sortedReferenceNames() []string {
	names := make([]string, 0, 3)
	for name := range SkillReferences() {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
