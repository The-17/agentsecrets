package commands

import "testing"

func TestNormalizeMigrationSource(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://api.agentsecrets.tech", "https://api.agentsecrets.tech"},
		{"https://api.agentsecrets.tech/api", "https://api.agentsecrets.tech"},
		{"https://api.agentsecrets.tech/api/", "https://api.agentsecrets.tech"},
		{"https://api.agentsecrets.tech/", "https://api.agentsecrets.tech"},
		{"api.agentsecrets.tech", "https://api.agentsecrets.tech"},
		{"http://localhost:8000", "http://localhost:8000"},
		{"localhost:8000/api", "http://localhost:8000"},
	}
	for _, c := range cases {
		if got := normalizeMigrationSource(c.in); got != c.want {
			t.Errorf("normalizeMigrationSource(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSummariseBundle(t *testing.T) {
	bundle := []byte(`{
		"version": "1.0",
		"user": {"email": "owner@example.com"},
		"workspaces": [
			{"projects": [{"secrets": [{}, {}]}, {"secrets": [{}]}]},
			{"projects": []}
		]
	}`)

	got := summariseBundle(bundle)
	if got.Email != "owner@example.com" {
		t.Errorf("email = %q", got.Email)
	}
	if got.Workspaces != 2 || got.Projects != 2 || got.Secrets != 3 {
		t.Errorf("counts = %+v, want {Workspaces:2 Projects:2 Secrets:3}", got)
	}
}
