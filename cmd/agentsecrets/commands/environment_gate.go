package commands

import (
	"fmt"
	"sync"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/ui"
)

// billingURL is where a workspace owner upgrades. It points at the dashboard
// rather than a marketing page because the upgrade applies to a workspace, not
// to the person reading it.
const billingURL = "https://agentsecrets.tech/dashboard/settings/billing"

// The three seams below are variables so the gate can be tested without a
// network, a config file, or a server. Everything else in this file is pure
// policy.
var (
	fetchWorkspacePlan = func(workspaceID string) string {
		client := app.API()
		if client == nil {
			return "unknown"
		}
		tier, err := api.FetchWorkspaceTier(client, workspaceID)
		if err != nil || tier == "" {
			return "unknown"
		}
		return tier
	}
	isSelfHostedServer = func() bool {
		return config.ResolveServerTarget("").IsSelfHost
	}
	currentWorkspaceID = func() string {
		if project, err := config.LoadProjectConfig(); err == nil && project != nil && project.WorkspaceID != "" {
			return project.WorkspaceID
		}
		return config.GetSelectedWorkspaceID()
	}
)

var (
	planMu    sync.Mutex
	planCache = map[string]string{}
)

// resolveWorkspacePlan asks for the workspace plan once per process. "unknown"
// is never cached, so a retry later in the same command can still succeed.
func resolveWorkspacePlan(workspaceID string) string {
	planMu.Lock()
	cached, ok := planCache[workspaceID]
	planMu.Unlock()
	if ok {
		return cached
	}

	plan := fetchWorkspacePlan(workspaceID)
	if plan != "unknown" {
		planMu.Lock()
		planCache[workspaceID] = plan
		planMu.Unlock()
	}
	return plan
}

// requireProForCustomEnvironment refuses a custom environment on a workspace
// that is not on Pro.
//
// Custom environments are a Pro feature, and the privilege is *creation*, not
// resolution: a Free workspace cannot start one at all. The answer comes from
// the control plane, which confirms a Free mirror against the resolver, so a
// workspace that has just upgraded is not refused by a stale local mirror.
//
// Three cases pass on purpose:
//   - a standard environment, which every project has;
//   - a self-hosted server, which has no resolver and therefore no plans;
//   - an answer that could not be fetched. Refusing paid work because a status
//     read failed would punish a paying customer for a flaky network, and the
//     resolver still refuses to *resolve* a custom environment without Pro, so
//     this path never grants the entitlement itself.
func requireProForCustomEnvironment(environment string) error {
	if config.IsStandardEnvironment(environment) {
		return nil
	}
	if isSelfHostedServer() {
		return nil
	}
	workspaceID := currentWorkspaceID()
	if workspaceID == "" {
		return nil
	}

	switch resolveWorkspacePlan(workspaceID) {
	case "pro":
		return nil
	case "free":
		return errors.New(
			errors.ErrUpgradeRequired,
			fmt.Sprintf("%q is a custom environment, and custom environments are a Pro feature", environment),
			fmt.Errorf("this workspace is on Free. Upgrade it at %s, then run the command again", billingURL),
		)
	default:
		ui.Warning(fmt.Sprintf("Could not confirm the workspace plan for %q.", environment))
		ui.Info("Continuing. The resolver still refuses a custom environment on a Free workspace.")
		return nil
	}
}
