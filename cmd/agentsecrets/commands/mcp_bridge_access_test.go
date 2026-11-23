package commands

import "testing"

func TestEveryBridgeVerbIsClassified(t *testing.T) {
	for verb := range bridgeDispatch {
		if _, ok := bridgeAccessLevels[verb]; !ok {
			t.Errorf("dispatch verb %q has no access classification", verb)
		}
	}
	for _, verb := range bridgeVerbs {
		if _, ok := bridgeDispatch[verb]; !ok {
			t.Errorf("advertised verb %q has no dispatch handler", verb)
		}
		if _, ok := bridgeAccessLevels[verb]; !ok {
			t.Errorf("advertised verb %q has no access classification", verb)
		}
	}
	for verb := range bridgeAccessLevels {
		if _, ok := bridgeDispatch[verb]; !ok {
			t.Errorf("classified verb %q has no dispatch handler", verb)
		}
	}
}

func TestBridgeCredentialVerbsAreGated(t *testing.T) {
	for _, verb := range []string{"auth.export", "agent.token_issue", "agent.token_rotate"} {
		if bridgeAccessLevels[verb] != bridgeCredential {
			t.Errorf("%q must be classified as a credential verb", verb)
		}
		if !bridgeWrites[verb] {
			t.Errorf("%q must require the human write switch", verb)
		}
	}
}
