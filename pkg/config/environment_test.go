package config

import (
	"strings"
	"testing"
)

// TestParseEnvironment locks the environment name rule to the control plane's:
// trim, lowercase, `^[a-z][a-z0-9-]{1,31}$`, reserved names rejected.
func TestParseEnvironment(t *testing.T) {
	valid := []struct {
		raw  string
		want string
	}{
		{"qa", "qa"},
		{"preview-pr-12", "preview-pr-12"},
		{"uat", "uat"},
		{"QA ", "qa"},
		{"  Staging  ", "staging"},
		{"development", "development"},
		{"production", "production"},
		{"a1", "a1"},
		{"a-very-long-environment-name-32", "a-very-long-environment-name-32"},
	}
	for _, tc := range valid {
		t.Run("accepts "+tc.raw, func(t *testing.T) {
			got, err := ParseEnvironment(tc.raw)
			if err != nil {
				t.Fatalf("ParseEnvironment(%q): unexpected error %v", tc.raw, err)
			}
			if got != tc.want {
				t.Errorf("ParseEnvironment(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}

	invalid := []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "", "environment name is required"},
		{"space inside", "has space", "invalid environment name"},
		{"leading hyphen", "-lead", "invalid environment name"},
		{"leading digit", "9qa", "invalid environment name"},
		{"too long", strings.Repeat("a", 40), "invalid environment name"},
		{"one character", "a", "invalid environment name"},
		{"space after uppercase", "Q A", "invalid environment name"},
		{"root", "root", "reserved"},
		{"admin", "admin", "reserved"},
		{"api", "api", "reserved"},
		{"internal", "internal", "reserved"},
		{"default", "default", "reserved"},
		{"reserved after normalization", " Admin ", "reserved"},
	}
	for _, tc := range invalid {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			got, err := ParseEnvironment(tc.raw)
			if err == nil {
				t.Fatalf("ParseEnvironment(%q) accepted %q, want an error", tc.raw, got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ParseEnvironment(%q) error = %q, want it to contain %q", tc.raw, err, tc.want)
			}
		})
	}

	t.Run("rejection names the rule", func(t *testing.T) {
		_, err := ParseEnvironment("Bad Name")
		if err == nil || !strings.Contains(err.Error(), EnvironmentNameRule) {
			t.Fatalf("error = %v, want it to state %q", err, EnvironmentNameRule)
		}
	})
}

func TestIsStandardEnvironment(t *testing.T) {
	for _, name := range StandardEnvironments {
		if !IsStandardEnvironment(name) {
			t.Errorf("IsStandardEnvironment(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"qa", "preview-pr-12", ""} {
		if IsStandardEnvironment(name) {
			t.Errorf("IsStandardEnvironment(%q) = true, want false", name)
		}
	}
}

func TestEnvironmentColumnLabel(t *testing.T) {
	cases := map[string]string{
		"development":    "DEV",
		"staging":        "STAGING",
		"production":     "PROD",
		"qa":             "QA",
		"preview-pr-12":  "PREVIEW_PR_12",
		"pre":            "PRE",
		"team-alpha-eu1": "TEAM_ALPHA_EU1",
	}
	for name, want := range cases {
		if got := EnvironmentColumnLabel(name); got != want {
			t.Errorf("EnvironmentColumnLabel(%q) = %q, want %q", name, got, want)
		}
	}
}
