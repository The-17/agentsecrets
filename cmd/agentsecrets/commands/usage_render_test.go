package commands

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/ui"
)

func captureRender(t *testing.T, err error) string {
	t.Helper()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	ui.ErrorWithSuggestions(err)
	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	if _, copyErr := io.Copy(&buf, r); copyErr != nil {
		t.Fatalf("read output: %v", copyErr)
	}
	return buf.String()
}

// A missing argument or a missing confirmation flag is a usage problem, not a
// crash. Rendering it as ERR-999 told the user to email engineering.
func TestUsageProblemRendersAsInvalidUsage(t *testing.T) {
	err := errors.New(errors.ErrUsage,
		`refusing to delete project "fmt-check" without confirmation in a non-interactive shell`,
		fmt.Errorf("re-run with --yes"))

	out := captureRender(t, err)

	for _, want := range []string{"[CLI-400]", "Invalid Usage", "--help"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "[ERR-999]") || strings.Contains(out, "Unexpected Error") {
		t.Errorf("usage problem rendered as an unexpected error:\n%s", out)
	}
	if strings.Contains(out, "engineering@theseventeen.co") {
		t.Errorf("usage problem told the user to email engineering:\n%s", out)
	}
}

// Hints attached to one failure must reach the user without turning the exit
// into a success, which is why they travel on the error.
func TestErrorSuggestionsReachTheRenderer(t *testing.T) {
	err := errors.WithSuggestions(errors.ErrInvalidCredentials, "login failed",
		fmt.Errorf("API error: invalid email or password (status 401)"),
		"Double check your email spelling and password.")

	out := captureRender(t, err)

	for _, want := range []string{"[AUTH-402]", "login failed", "Double check your email spelling and password."} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}
