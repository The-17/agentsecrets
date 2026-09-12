package commands

import (
	"reflect"
	"sort"
	"testing"
)

func TestHostsFromSecrets(t *testing.T) {
	cases := []struct {
		name    string
		secrets map[string]string
		want    []string
	}{
		{
			name:    "connection string with credentials",
			secrets: map[string]string{"DATABASE_URL": "postgres://user:pw@db.internal:5432/app"},
			want:    []string{"db.internal"},
		},
		{
			name:    "https url",
			secrets: map[string]string{"REDIS_URL": "https://cache.example.com/0"},
			want:    []string{"cache.example.com"},
		},
		{
			name:    "bare host value",
			secrets: map[string]string{"PGHOST": "db.example.com"},
			want:    []string{"db.example.com"},
		},
		{
			name:    "host= form in a connection string",
			secrets: map[string]string{"CONN": "Server=smtp.gmail.com;Port=587;User=x"},
			want:    []string{"smtp.gmail.com"},
		},
		{
			name:    "opaque secret yields nothing",
			secrets: map[string]string{"STRIPE_KEY": "sk_live_abc123def456", "JWT": "eyJhbGciOi"},
			want:    nil,
		},
		{
			name:    "localhost kept, bare word dropped",
			secrets: map[string]string{"A": "localhost:3000", "B": "development"},
			want:    []string{"localhost"},
		},
		{
			name:    "duplicates collapsed",
			secrets: map[string]string{"A": "https://api.stripe.com/v1", "B": "api.stripe.com"},
			want:    []string{"api.stripe.com"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hostsFromSecrets(c.secrets)
			sort.Strings(got)
			want := append([]string(nil), c.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("hostsFromSecrets(%v) = %v, want %v", c.secrets, got, want)
			}
		})
	}
}

func TestHostAllowed(t *testing.T) {
	allow := []string{"api.stripe.com", "*.example.com", ".internal.net"}
	cases := []struct {
		host string
		want bool
	}{
		{"api.stripe.com", true},
		{"API.STRIPE.COM", true},
		{"evil.com", false},
		{"a.example.com", true},
		{"example.com", false}, // wildcard covers subdomains, not the apex
		{"db.internal.net", true},
		{"internal.net", false},
	}
	for _, c := range cases {
		if got := hostAllowed(c.host, allow); got != c.want {
			t.Errorf("hostAllowed(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}
