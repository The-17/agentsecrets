package commands

import "testing"

func TestWorkflowsAreOptIn(t *testing.T) {
	flag := initCmd.Flags().Lookup("workflows")
	if flag == nil {
		t.Fatal("init should expose a --workflows flag")
	}
	if flag.DefValue != "false" {
		t.Errorf("workflow files must be opt-in, got default %q", flag.DefValue)
	}
}
