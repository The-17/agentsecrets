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

// A billing refusal must not render as ERR-999 "Unexpected Error": that reads
// like a crash and buries the upgrade path the user needs.
func TestUpgradeRequiredRendersAsABillingError(t *testing.T) {
	err := errors.New(
		errors.ErrUpgradeRequired,
		`"prod-eu" is a custom environment, and custom environments are a Pro feature`,
		fmt.Errorf("this workspace is on Free. Upgrade it at %s, then run the command again", billingURL),
	)

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	ui.ErrorWithSuggestions(err)
	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read output: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"[BIL-402]", "Upgrade Required", "dashboard/settings/billing"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "[ERR-999]") {
		t.Errorf("billing refusal rendered as an unexpected error:\n%q", out)
	}
	if !strings.Contains(out, "[BIL-402]") || !strings.Contains(out, "Upgrade Required") || !strings.Contains(out, "dashboard/settings/billing") {
		t.Fatalf("rendered output was:\n%q", out)
	}
}
