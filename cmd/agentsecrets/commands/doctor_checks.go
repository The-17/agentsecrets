package commands

import (
	"fmt"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/keychainauth"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/projects"
	"github.com/The-17/agentsecrets/pkg/workspaces"
)

// appendSystemChecks adds the five checks from the doctor scope: config
// coherence, session/account, workspace key, active project, and server
// reachability. They append findings to the same report the keychain check uses,
// so the existing renderer and JSON output surface them without a rewrite.
//
// None are auto-repairable here. Their Remedy names the one command that fixes
// the problem, because the scope puts any repair needing a password out of
// bounds for --check-only, and a doctor that invents a fix it cannot run would
// be worse than silent.
func appendSystemChecks(report *keychainauth.Report) {
	cfg, cfgErr := config.LoadGlobalConfig()
	if cfgErr != nil {
		report.Findings = append(report.Findings, keychainauth.Finding{
			ID:     "config",
			Title:  "AgentSecrets config is unreadable",
			Status: keychainauth.StatusBroken,
			Detail: cfgErr.Error(),
			Remedy: "Repair or remove the config file, then run 'agentsecrets login'.",
		})
		return // without a config the rest cannot be judged
	}
	if cfg != nil && cfg.Email != "" {
		report.Findings = append(report.Findings, keychainauth.Finding{
			ID:     "config",
			Title:  "AgentSecrets config is readable",
			Status: keychainauth.StatusOK,
			Detail: fmt.Sprintf("Account: %s", cfg.Email),
		})
	}

	// Session and server reachability are coupled: one cheap authenticated call
	// tells them apart, which is the whole point of the server check.
	if !config.IsAuthenticated() {
		report.Findings = append(report.Findings, keychainauth.Finding{
			ID:     "session",
			Title:  "You are not signed in",
			Status: keychainauth.StatusBroken,
			Detail: "No stored session for the configured account.",
			Remedy: "Run 'agentsecrets login'.",
		})
		return // workspace and project checks all need an account
	}

	wsList, wsErr := app.Workspaces().List()
	switch kind, detail := classifyAPICall(wsErr); kind {
	case "auth":
		report.Findings = append(report.Findings, keychainauth.Finding{
			ID:     "session",
			Title:  "Your session is no longer accepted by the server",
			Status: keychainauth.StatusBroken,
			Detail: detail,
			Remedy: "Run 'agentsecrets login' to refresh your session.",
		})
		return
	case "network":
		report.Findings = append(report.Findings, keychainauth.Finding{
			ID:     "server",
			Title:  "AgentSecrets server is unreachable",
			Status: keychainauth.StatusBroken,
			Detail: detail,
			Remedy: "Check your network connection and the server URL in 'agentsecrets config'.",
		})
		report.Findings = append(report.Findings, keychainauth.Finding{
			ID:     "session",
			Title:  "Session is stored locally",
			Status: keychainauth.StatusOK,
		})
		return // without the server, workspace/project checks are indeterminate
	case "other":
		report.Findings = append(report.Findings, keychainauth.Finding{
			ID:     "server",
			Title:  "Could not reach the AgentSecrets server",
			Status: keychainauth.StatusBroken,
			Detail: detail,
			Remedy: "Check the server URL and your network, then re-run 'agentsecrets doctor'.",
		})
		report.Findings = append(report.Findings, keychainauth.Finding{
			ID:     "session",
			Title:  "Session is stored locally",
			Status: keychainauth.StatusOK,
		})
		return
	}
	report.Findings = append(report.Findings, keychainauth.Finding{
		ID:     "server",
		Title:  "AgentSecrets server is reachable",
		Status: keychainauth.StatusOK,
	})
	report.Findings = append(report.Findings, keychainauth.Finding{
		ID:     "session",
		Title:  "Signed in and the server accepts your session",
		Status: keychainauth.StatusOK,
	})

	// Workspace key.
	appendWorkspaceCheck(report, wsList)

	// Active project.
	appendProjectCheck(report)
}

func appendWorkspaceCheck(report *keychainauth.Report, wsList []workspaces.Workspace) {
	wsID := config.GetSelectedWorkspaceID()
	if wsID == "" {
		report.Findings = append(report.Findings, keychainauth.Finding{
			ID:     "workspace",
			Title:  "No workspace selected",
			Status: keychainauth.StatusWarn,
			Detail: "Run 'agentsecrets workspace switch' to pick one.",
		})
		return
	}

	var found *workspaces.Workspace
	for i := range wsList {
		if wsList[i].ID == wsID {
			found = &wsList[i]
			break
		}
	}
	name := wsID
	if found != nil {
		name = found.Name
	}
	if found == nil {
		report.Findings = append(report.Findings, keychainauth.Finding{
			ID:     "workspace",
			Title:  "Selected workspace is not visible to this account",
			Status: keychainauth.StatusBroken,
			Detail: fmt.Sprintf("Workspace %s is not in the list returned by the server.", wsID),
			Remedy: "Run 'agentsecrets workspace switch' to pick a workspace you belong to.",
		})
		return
	}

	if _, kerr := keyring.GetWorkspaceKey(wsID); kerr != nil {
		report.Findings = append(report.Findings, keychainauth.Finding{
			ID:     "workspace",
			Title:  fmt.Sprintf("Workspace %q key is missing locally", name),
			Status: keychainauth.StatusBroken,
			Detail: "The key that decrypts this workspace's secrets is not in the local credential store.",
			Remedy: fmt.Sprintf("Run 'agentsecrets workspace refresh'. If it is still missing, ask an admin to re-invite you: agentsecrets workspace invite %s", config.GetEmail()),
		})
		return
	}
	report.Findings = append(report.Findings, keychainauth.Finding{
		ID:     "workspace",
		Title:  fmt.Sprintf("Workspace %q is openable", name),
		Status: keychainauth.StatusOK,
	})
}

func appendProjectCheck(report *keychainauth.Report) {
	proj, projErr := config.LoadProjectConfig()
	if projErr != nil || proj == nil || proj.ProjectID == "" {
		report.Findings = append(report.Findings, keychainauth.Finding{
			ID:     "project",
			Title:  "No project linked to this directory",
			Status: keychainauth.StatusWarn,
			Detail: "Run 'agentsecrets project use <name>' or 'agentsecrets project create <name>'.",
		})
		return
	}

	plist, perr := app.Projects().List()
	if perr != nil {
		report.Findings = append(report.Findings, keychainauth.Finding{
			ID:     "project",
			Title:  "Could not confirm the linked project",
			Status: keychainauth.StatusWarn,
			Detail: perr.Error(),
		})
		return
	}

	var found *projects.Project
	for i := range plist {
		if plist[i].ID == proj.ProjectID {
			found = &plist[i]
			break
		}
	}
	if found == nil {
		report.Findings = append(report.Findings, keychainauth.Finding{
			ID:     "project",
			Title:  "Linked project no longer exists",
			Status: keychainauth.StatusBroken,
			Detail: fmt.Sprintf("project.json points at %s, which is not in your projects.", proj.ProjectID),
			Remedy: "Run 'agentsecrets project use <name>' to link a project you can see.",
		})
		return
	}

	env := config.ResolveEnvironment()
	detail := fmt.Sprintf("Active environment: %s", env)
	if !isStandardEnvironment(env) {
		detail += " (custom environments are a Pro feature; the workspace must be on Pro)"
	}
	report.Findings = append(report.Findings, keychainauth.Finding{
		ID:     "project",
		Title:  fmt.Sprintf("Project %q is linked", found.Name),
		Status: keychainauth.StatusOK,
		Detail: detail,
	})
}

func isStandardEnvironment(env string) bool {
	switch env {
	case "development", "staging", "production":
		return true
	}
	return false
}

// classifyAPICall turns an error from an authenticated request into a class the
// doctor can name. ok means the call succeeded.
func classifyAPICall(err error) (string, string) {
	if err == nil {
		return "ok", ""
	}
	code := errors.FromError(err).Code
	switch code {
	case errors.ErrUnauthorized, errors.ErrInvalidCredentials, errors.ErrForbidden:
		return "auth", err.Error()
	case errors.ErrConnection, errors.ErrConnectionTimeout:
		return "network", err.Error()
	default:
		return "other", err.Error()
	}
}
