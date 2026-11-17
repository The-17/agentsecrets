package commands

import (
	"strings"
	"testing"
)

// TestValidateRotationArmFlags locks the CLI contract for rotation arming:
// arming needs a positive period, disarming needs none, and the contradictory
// combinations are rejected before any API call.
func TestValidateRotationArmFlags(t *testing.T) {
	cases := []struct {
		name       string
		disable    bool
		periodDays int
		wantErr    bool
	}{
		{name: "arm with one day", disable: false, periodDays: 1},
		{name: "arm with thirty days", disable: false, periodDays: 30},
		{name: "disarm with no period", disable: true, periodDays: 0},
		{name: "both flags", disable: true, periodDays: 30, wantErr: true},
		{name: "neither flag", disable: false, periodDays: 0, wantErr: true},
		{name: "negative period", disable: false, periodDays: -1, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRotationArmFlags(tc.disable, tc.periodDays)
			if tc.wantErr && err == nil {
				t.Fatal("want an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want no error, got %v", err)
			}
		})
	}
}

// TestAdapterRefID locks the accepted pin shape so a malformed ref is refused
// before it is stored, instead of failing later during an unattended sweep.
func TestAdapterRefID(t *testing.T) {
	valid := "postgres@1.0.0#sha256:4b42cba52172229f621fc34d320e2b107ee6ad0536ed03cc0aa9e4cf9c8bf0d7"
	if id, err := adapterRefID(valid); err != nil || id != "postgres" {
		t.Fatalf("valid pin: id=%q err=%v", id, err)
	}
	if id, err := adapterRefID("cloudflare-api-token@1.2.0"); err != nil || id != "cloudflare-api-token" {
		t.Fatalf("bare pin: id=%q err=%v", id, err)
	}
	for _, bad := range []string{
		"postgres@1.0.0#sha256:short",
		"postgres@1.0",
		"postgres",
		"postgres@1.0.0#sha256:" + "g" + strings.Repeat("0", 63),
	} {
		if _, err := adapterRefID(bad); err == nil {
			t.Errorf("accepted malformed ref %q", bad)
		}
	}
}
