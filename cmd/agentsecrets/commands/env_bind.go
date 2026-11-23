package commands

import (
	"fmt"
	"strings"

	clierrors "github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/projects"
	"github.com/The-17/agentsecrets/pkg/ui"
)

const maxProjectSuggestions = 5

// directoryProjectMatch finds a project whose name equals dirName, ignoring
// case. Only an exact match is automatic. A fuzzy match could bind a developer
// to the wrong project on a machine that holds several similarly named ones.
func directoryProjectMatch(projs []projects.Project, dirName string) (*projects.Project, bool) {
	var match *projects.Project
	for i := range projs {
		if !strings.EqualFold(projs[i].Name, dirName) {
			continue
		}
		if match != nil {
			return nil, false // ambiguous: let the user choose with project use
		}
		match = &projs[i]
	}
	return match, match != nil
}

// noProjectDetail explains the unlinked-directory state with the verb that
// actually applies. Telling a developer with zero projects to run `project use`
// sends them to a command that cannot succeed.
func noProjectDetail(projs []projects.Project, listErr error) string {
	cloudHint := "Or pass AGENTSECRETS_TOKEN / --cloud for cloud resolution."
	if listErr != nil {
		return "This directory is not linked to a project. Create one with 'agentsecrets project create <name>', or link an existing one with 'agentsecrets project use <name>'. " + cloudHint
	}
	if len(projs) == 0 {
		return "This directory is not linked to a project yet. Create one with 'agentsecrets project create <name>'. " + cloudHint
	}

	names := make([]projects.Project, 0, len(projs))
	if len(projs) > maxProjectSuggestions {
		names = append(names, projs[:maxProjectSuggestions]...)
	} else {
		names = append(names, projs...)
	}
	listed := make([]string, 0, len(names))
	for _, p := range names {
		listed = append(listed, p.Name)
	}
	return fmt.Sprintf("Link this directory with 'agentsecrets project use <name>'. Projects: %s. %s",
		strings.Join(listed, ", "), cloudHint)
}

// noActiveProjectError is the coded error for an unlinked directory. The detail
// is specific enough to be the only line a developer needs to read.
func noActiveProjectError(projs []projects.Project, listErr error) error {
	return clierrors.New(clierrors.ErrUsage, "no active project",
		fmt.Errorf("%s", noProjectDetail(projs, listErr)))
}

// bindProjectFromDirectory links the current directory when its name exactly
// matches one project in the selected workspace. The prompt is one line and
// declining leaves the directory untouched. Non-interactive callers never get
// a prompt: they get the explicit create/use guidance from noProjectDetail.
func bindProjectFromDirectory(projs []projects.Project) error {
	match, unique := directoryProjectMatch(projs, initProjectNameDefault())
	if !unique || match == nil {
		return nil
	}

	if !confirmProceed(false, fmt.Sprintf("This directory is not linked. Use project %q here? [y/N] ", match.Name)) {
		return nil
	}
	if _, err := app.Projects().Use(match.Name); err != nil {
		return fmt.Errorf("could not link project %q: %w", match.Name, err)
	}
	ui.Success(fmt.Sprintf("Linked this directory to project %q.", match.Name))
	return nil
}
