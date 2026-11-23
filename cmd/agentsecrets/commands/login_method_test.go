package commands

import "testing"

func TestResolveLoginMethod(t *testing.T) {
	cases := []struct {
		name                     string
		recovery, google, github bool
		email                    string
		interactive              bool
		want                     loginMethod
		wantErr                  bool
	}{
		{name: "recovery beats nothing", recovery: true, want: methodRecovery},
		{name: "google", google: true, want: methodGoogle},
		{name: "github", github: true, want: methodGithub},
		{name: "email", email: "a@example.com", want: methodEmailWith},
		{name: "picker when interactive", interactive: true, want: methodPicker},
		{name: "password for scripts", want: methodPassword},
		{name: "recovery and email conflict", recovery: true, email: "a@example.com", wantErr: true},
		{name: "recovery and provider conflict", recovery: true, google: true, wantErr: true},
		{name: "two providers conflict", google: true, github: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveLoginMethod(tc.recovery, tc.google, tc.github, tc.email, tc.interactive)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected conflicting flags to be rejected")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
