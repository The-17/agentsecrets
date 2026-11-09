package capabilities

import "testing"

func TestParseScopes_EmptyReturnsNil(t *testing.T) {
	got, err := ParseScopes(nil)
	if err != nil || got != nil {
		t.Fatalf("nil list: got %v, err %v; want (nil, nil)", got, err)
	}
	got, err = ParseScopes([]string{"", "  "})
	if err != nil || got != nil {
		t.Fatalf("blank list: got %v, err %v; want (nil, nil)", got, err)
	}
}

func TestParseScopes_Grantable(t *testing.T) {
	got, err := ParseScopes([]string{"secrets:env,secrets:proxy"})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || *got.CanEnvRead != true || *got.CanProxyResolve != true {
		t.Fatalf("want both scopes granted, got %+v", got)
	}
}

func TestParseScopes_CaseInsensitiveAndDedup(t *testing.T) {
	got, err := ParseScopes([]string{"Secrets:Env", "SECRETS:PROXY", "secrets:env"})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || *got.CanEnvRead != true || *got.CanProxyResolve != true {
		t.Fatalf("want both scopes granted once, got %+v", got)
	}
}

func TestParseScopes_SpaceSeparated(t *testing.T) {
	got, err := ParseScopes([]string{"secrets:env secrets:proxy"})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || *got.CanEnvRead != true || *got.CanProxyResolve != true {
		t.Fatalf("space-separated parse failed: %+v", got)
	}
}

// The resolver honors secrets:read and secrets:admin, but the control plane
// does not mint them. Accepting them silently would be a privilege lie.
func TestParseScopes_FailClosedOnUnsupported(t *testing.T) {
	cases := [][]string{
		{"secrets:read"},
		{"secrets:admin"},
		{"secrets:env", "secrets:read"},
		{"bogus:scope"},
	}
	for _, c := range cases {
		got, err := ParseScopes(c)
		if err == nil {
			t.Errorf("scope set %v should fail closed, got %+v", c, got)
		}
		if !containsAll(err.Error(), "not grantable", "secrets:env", "secrets:proxy") {
			t.Errorf("error %q should name the supported scopes", err.Error())
		}
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !contains(s, sub) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
