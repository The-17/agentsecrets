package commands

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/The-17/agentsecrets/pkg/config"
)

// confirmYN reads a y/n answer from stdin (line-based: only "y" or "yes"
// proceed; anything else, including "y <extra>", declines — stricter than
// token scanning, deliberately so for destructive actions).
func confirmYN() bool {
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes"
}

// confirmProceed prints prompt and asks once. skip bypasses the question
// (wired to --confirm/--force flags by callers). Returns false when the
// action must not proceed; callers print their own abort wording.
func confirmProceed(skip bool, prompt string) bool {
	if skip {
		return true
	}
	fmt.Print(prompt)
	return confirmYN()
}

// requireWorkspace returns the selected workspace id or the standard
// guidance error when none is selected.
func requireWorkspace() (string, error) {
	workspaceID := config.GetSelectedWorkspaceID()
	if workspaceID == "" {
		return "", fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
	}
	return workspaceID, nil
}

// confirmHuh asks via an interactive form. Optional affirmative/negative
// labels (logout customizes them); default huh labels otherwise.
func confirmHuh(title, description string, affirmNeg ...string) bool {
	var confirmed bool
	b := huh.NewConfirm().Title(title).Value(&confirmed)
	if description != "" {
		b = b.Description(description)
	}
	if len(affirmNeg) == 2 {
		b = b.Affirmative(affirmNeg[0]).Negative(affirmNeg[1])
	}
	return b.Run() == nil && confirmed
}
