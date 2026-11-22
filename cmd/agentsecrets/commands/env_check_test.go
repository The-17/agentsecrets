package commands

import (
	"errors"
	"strings"
	"testing"

	"github.com/The-17/agentsecrets/pkg/gateway"
)

func TestEnvCheckLines(t *testing.T) {
	sel := gateway.Selection{Mode: gateway.ModeLocal, Source: "flag"}
	lines := envCheckLines(sel, "development", "billing-api", "", []string{"STRIPE_KEY", "DATABASE_URL"}, false, nil)
	joined := strings.Join(lines, "\n")

	for _, want := range []string{
		"Mode: local (selected by flag)",
		"Environment: development",
		"Project: billing-api",
		"Secrets: 2 key(s)",
		"Injection would be allowed",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
	if !strings.Contains(joined, "  DATABASE_URL\n  STRIPE_KEY") {
		t.Errorf("keys should be sorted, got:\n%s", joined)
	}
}

func TestEnvCheckLinesNeverShowsValues(t *testing.T) {
	sel := gateway.Selection{Mode: gateway.ModeCloud, Source: "flag"}
	lines := envCheckLines(sel, "", "", "AGENTSECRETS_TOKEN", []string{"DATABASE_URL"}, true, errors.New("missing key"))
	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "value") || strings.Contains(joined, "sk_live") {
		t.Errorf("check output must contain names only, got:\n%s", joined)
	}
	if !strings.Contains(joined, "Token source: AGENTSECRETS_TOKEN") {
		t.Errorf("cloud check should name the token source, got:\n%s", joined)
	}
	if !strings.Contains(joined, "Injection would be refused: missing key") {
		t.Errorf("check should report the verdict, got:\n%s", joined)
	}
}
