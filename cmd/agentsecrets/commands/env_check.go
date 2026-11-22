package commands

import (
	"fmt"
	"sort"

	"github.com/The-17/agentsecrets/pkg/gateway"
)

// envCheckLines formats the diagnostic view of an env run. It receives key
// names only. No value enters this function, so a check cannot become a way to
// read secrets out of a local or cloud resolution.
func envCheckLines(selection gateway.Selection, envName, projectName, tokenSource string, keys []string, guardInstalled bool, verdict error) []string {
	lines := []string{
		fmt.Sprintf("Mode: %s (selected by %s)", selection.Mode, selection.Source),
		fmt.Sprintf("Environment: %s", displayOr(envName, "active")),
	}
	if projectName != "" {
		lines = append(lines, fmt.Sprintf("Project: %s", projectName))
	}
	if selection.Mode == gateway.ModeCloud && tokenSource != "" {
		lines = append(lines, fmt.Sprintf("Token source: %s", tokenSource))
	}

	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)
	lines = append(lines, fmt.Sprintf("Secrets: %d key(s)", len(sorted)))
	for _, key := range sorted {
		lines = append(lines, "  "+key)
	}

	if guardInstalled {
		lines = append(lines, "Guard: pinned library active")
	} else {
		lines = append(lines, "Guard: parent-side output filtering only")
	}
	if verdict != nil {
		lines = append(lines, "Injection would be refused: "+verdict.Error())
	} else {
		lines = append(lines, "Injection would be allowed")
	}
	return lines
}

func displayOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
