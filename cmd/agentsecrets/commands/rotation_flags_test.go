package commands

import "testing"

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
