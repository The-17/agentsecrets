package commands

import (
	"strings"
	"testing"

	"github.com/The-17/agentsecrets/pkg/errors"
)

// `secrets list --env staging` used to be an unknown flag, even though every
// write command takes --env. Narrowing to one environment is now supported and
// must refuse a name the project does not have rather than print an empty table.
func TestFilterEnvs(t *testing.T) {
	envs := []string{"development", "staging", "production"}

	got, err := filterEnvs(envs, "")
	if err != nil {
		t.Fatalf("no filter: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("no filter dropped environments: %v", got)
	}

	got, err = filterEnvs(envs, "staging")
	if err != nil {
		t.Fatalf("known environment: %v", err)
	}
	if len(got) != 1 || got[0] != "staging" {
		t.Fatalf("filter returned %v, want [staging]", got)
	}

	_, err = filterEnvs(envs, "prod-eu")
	if err == nil {
		t.Fatal("unknown environment was accepted")
	}
	cliErr, ok := err.(*errors.CLIError)
	if !ok || cliErr.Code != errors.ErrUsage {
		t.Fatalf("unknown environment error = %T %v, want CLI-400", err, err)
	}
	if !strings.Contains(err.Error(), "development, staging, production") {
		t.Errorf("error does not list what exists: %v", err)
	}
}
