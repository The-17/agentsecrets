package commands

import "testing"

func TestStatusVersionDisplay(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    string
	}{
		{"4.0.0-dev", "3.3.6", "4.0.0-dev (dev build)"},
		{"3.2.3", "3.3.6", "3.2.3 (outdated, 3.3.6 available)"},
		{"3.3.6", "3.3.6", "3.3.6 (up to date)"},
		{"3.3.6", "", "3.3.6"},
	}

	for _, tt := range tests {
		if got := statusVersionDisplay(tt.current, tt.latest); got != tt.want {
			t.Errorf("statusVersionDisplay(%q, %q) = %q, want %q", tt.current, tt.latest, got, tt.want)
		}
	}
}
