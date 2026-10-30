package commands

import (
	stderrors "errors"
	"testing"

	"github.com/spf13/cobra"

	clierrors "github.com/The-17/agentsecrets/pkg/errors"
)

// A conflicting pair of mode flags is user input, not a crash. Rendering it as
// ERR-999 told the user to email engineering for a typo. Pin the taxonomy so
// the renderer keeps saying CLI-400 with the usage hint.
func TestResolveCallModeConflictIsUsageError(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().Bool("cloud", true, "")
	cmd.Flags().Bool("local", true, "")

	_, err := resolveCallMode(cmd)
	if err == nil {
		t.Fatal("expected an error for --cloud + --local")
	}
	var cliErr *clierrors.CLIError
	if !stderrors.As(err, &cliErr) {
		t.Fatalf("error is %T, want *errors.CLIError", err)
	}
	if cliErr.Code != clierrors.ErrUsage {
		t.Fatalf("code = %s, want %s", cliErr.Code, clierrors.ErrUsage)
	}
}
