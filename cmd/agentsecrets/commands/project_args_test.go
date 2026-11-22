package commands

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/term"
)

func TestProjectCreateArgs(t *testing.T) {
	t.Run("accepts a name", func(t *testing.T) {
		if err := projectCreateArgs(projectCreateCmd, []string{"billing-api"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("accepts name and description", func(t *testing.T) {
		if err := projectCreateArgs(projectCreateCmd, []string{"billing-api", "Payments"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("rejects extra arguments", func(t *testing.T) {
		err := projectCreateArgs(projectCreateCmd, []string{"a", "b", "c"})
		if err == nil {
			t.Fatal("expected more than two arguments to be rejected")
		}
	})

	t.Run("requires a name without a terminal", func(t *testing.T) {
		err := projectCreateArgs(projectCreateCmd, nil)
		if term.IsTerminal(int(os.Stdin.Fd())) {
			if err != nil {
				t.Fatalf("an interactive shell may prompt for the name, got %v", err)
			}
			return
		}
		if err == nil {
			t.Fatal("expected a usage error when there is no terminal to prompt")
		}
		if !strings.Contains(err.Error(), "name is required") {
			t.Errorf("error should say the name is required, got %v", err)
		}
	})
}

func TestIsProjectNotFound(t *testing.T) {
	if isProjectNotFound(nil) {
		t.Error("nil is not a not-found error")
	}
	if !isProjectNotFound(errString("use project: 404 not found")) {
		t.Error("a 404 should count as not found")
	}
	if isProjectNotFound(errString("use project: connection refused")) {
		t.Error("a transport failure must not be treated as not found")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
