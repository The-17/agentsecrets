package commands

import (
	"strings"
	"testing"

	"github.com/The-17/agentsecrets/pkg/config"
)

// withGate swaps the three policy seams for one test and reports how many times
// the plan was fetched. Nothing here touches the network, the filesystem, or a
// server.
func withGate(t *testing.T, plan string, selfHosted bool, workspaceID string) *int {
	t.Helper()

	prevFetch, prevSelfHost, prevWorkspace := fetchWorkspacePlan, isSelfHostedServer, currentWorkspaceID
	resetPlanCache()
	t.Cleanup(func() {
		fetchWorkspacePlan, isSelfHostedServer, currentWorkspaceID = prevFetch, prevSelfHost, prevWorkspace
		resetPlanCache()
	})

	calls := 0
	fetchWorkspacePlan = func(string) string {
		calls++
		return plan
	}
	isSelfHostedServer = func() bool { return selfHosted }
	currentWorkspaceID = func() string { return workspaceID }
	return &calls
}

func resetPlanCache() {
	planMu.Lock()
	planCache = map[string]string{}
	planMu.Unlock()
}

func TestStandardEnvironmentsNeverAskForAPlan(t *testing.T) {
	for _, environment := range config.StandardEnvironments {
		t.Run(environment, func(t *testing.T) {
			calls := withGate(t, "free", false, "ws-1")
			if err := requireProForCustomEnvironment(environment); err != nil {
				t.Fatalf("standard environment %q was refused: %v", environment, err)
			}
			if *calls != 0 {
				t.Fatalf("standard environment %q asked the control plane %d times", environment, *calls)
			}
		})
	}
}

func TestCustomEnvironmentIsRefusedOnFree(t *testing.T) {
	withGate(t, "free", false, "ws-1")

	err := requireProForCustomEnvironment("qa")
	if err == nil {
		t.Fatal("a Free workspace created a custom environment")
	}
	for _, want := range []string{"qa", "Pro", billingURL} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}
}

func TestCustomEnvironmentIsAllowedOnPro(t *testing.T) {
	calls := withGate(t, "pro", false, "ws-1")

	if err := requireProForCustomEnvironment("qa"); err != nil {
		t.Fatalf("Pro workspace was refused a custom environment: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("expected exactly one plan read, got %d", *calls)
	}
}

func TestSelfHostedServerSkipsThePlanRead(t *testing.T) {
	calls := withGate(t, "free", true, "ws-1")

	if err := requireProForCustomEnvironment("qa"); err != nil {
		t.Fatalf("a self-hosted server was refused a custom environment: %v", err)
	}
	if *calls != 0 {
		t.Fatalf("a self-hosted server asked for a plan %d times", *calls)
	}
}

func TestUnknownPlanDoesNotBlock(t *testing.T) {
	withGate(t, "unknown", false, "ws-1")

	if err := requireProForCustomEnvironment("qa"); err != nil {
		t.Fatalf("an unconfirmed plan blocked a custom environment: %v", err)
	}
}

func TestNoWorkspaceDoesNotBlock(t *testing.T) {
	calls := withGate(t, "free", false, "")

	if err := requireProForCustomEnvironment("qa"); err != nil {
		t.Fatalf("a missing workspace id blocked a custom environment: %v", err)
	}
	if *calls != 0 {
		t.Fatalf("a missing workspace id asked for a plan %d times", *calls)
	}
}

func TestPlanIsReadOncePerProcess(t *testing.T) {
	calls := withGate(t, "pro", false, "ws-1")

	for _, environment := range []string{"qa", "qa2", "qa"} {
		if err := requireProForCustomEnvironment(environment); err != nil {
			t.Fatalf("%q: %v", environment, err)
		}
	}
	if *calls != 1 {
		t.Fatalf("expected one plan read for one workspace, got %d", *calls)
	}
}

func TestUnknownPlanIsNotCached(t *testing.T) {
	calls := withGate(t, "unknown", false, "ws-1")

	_ = requireProForCustomEnvironment("qa")
	_ = requireProForCustomEnvironment("qa")
	if *calls != 2 {
		t.Fatalf("an unconfirmed plan was cached: %d reads", *calls)
	}
}

func TestEnvCreateRefusesAStandardEnvironment(t *testing.T) {
	withGate(t, "pro", false, "ws-1")

	err := runEnvCreate(nil, []string{"staging"})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("creating a standard environment did not say it exists: %v", err)
	}
}

func TestEnvCreateRefusesFreeBeforeWritingAnything(t *testing.T) {
	withGate(t, "free", false, "ws-1")

	if err := runEnvCreate(nil, []string{"qa"}); err == nil {
		t.Fatal("a Free workspace created a custom environment")
	}
}

func TestEnvSwitchIsGatedForCustomNames(t *testing.T) {
	withGate(t, "free", false, "ws-1")

	if err := runEnvSwitch(nil, []string{"qa"}); err == nil {
		t.Fatal("a Free workspace switched to a custom environment")
	}
}

func TestSecretsSetIsGatedForCustomNames(t *testing.T) {
	withGate(t, "free", false, "ws-1")

	if _, err := storeSecretValues(map[string]string{"K": "v"}, "qa", true); err == nil {
		t.Fatal("a Free workspace wrote a secret into a custom environment")
	}
}
