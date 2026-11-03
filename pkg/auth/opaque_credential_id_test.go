package auth

import "testing"

// The browser (agentsecrets-website/src/lib/opaque-wasm.ts) derives the OPAQUE
// credential id as UUIDv5(namespace, lowercase(email)). The id is authenticated
// inside the OPAQUE record, so if the two clients ever disagree an account
// enrolled in one cannot log in from the other. The expected values below are
// computed independently with Python's uuid.uuid5 in the same namespace.
func TestOpaqueCredentialIDMatchesBrowser(t *testing.T) {
	cases := []struct {
		email string
		want  string
	}{
		{"test@example.com", "3df16d73-1694-500b-8507-78ec2acda1f7"},
		{"opaque-test@example.com", "0e6acf9f-4723-5965-8654-0ca3946867ef"},
		// Case and surrounding whitespace are normalised, so the same account
		// keeps one id regardless of how the address was typed.
		{"  TEST@Example.COM ", "3df16d73-1694-500b-8507-78ec2acda1f7"},
	}
	for _, tc := range cases {
		if got := opaqueCredentialID(tc.email); got != tc.want {
			t.Errorf("opaqueCredentialID(%q) = %q, want %q", tc.email, got, tc.want)
		}
	}
}
