package keychainauth

import "testing"

func TestRetrySafe(t *testing.T) {
	for _, action := range []string{actionRead, actionWrite, actionDelete, actionSearch} {
		if !retrySafe(request{Action: action}) {
			t.Errorf("%q should be replayable after a lost response", action)
		}
	}
	if retrySafe(request{Action: "unknown"}) {
		t.Error("an unknown action must not be replayed")
	}
}
