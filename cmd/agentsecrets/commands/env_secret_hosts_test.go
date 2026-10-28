package commands

import "testing"

// A secret whose entire value is a host is a stored value. The host derived from
// it must not be shown, or written to the audit trail, because it is the value
// verbatim. A host parsed out of a larger value stays showable.
func TestHostThatIsTheStoredValueIsNotShown(t *testing.T) {
	secrets := map[string]string{
		"EMAIL_HOST":   "smtp-relay.brevo.com",
		"DATABASE_URL": "postgres://user:pass@db.internal:5432/app",
	}

	hosts := hostsFromSecrets(secrets)
	shown, hidden := splitSecretHosts(hosts, secrets)

	if len(hidden) != 1 || hidden[0] != "smtp-relay.brevo.com" {
		t.Fatalf("hidden = %v, want [smtp-relay.brevo.com]", hidden)
	}
	if len(shown) != 1 || shown[0] != "db.internal" {
		t.Fatalf("shown = %v, want [db.internal]", shown)
	}

	for _, h := range auditableHosts(hosts, secrets) {
		if h == "smtp-relay.brevo.com" {
			t.Errorf("audit hosts still contain the stored value")
		}
	}

	keys := secretKeysNamingHosts(hidden, secrets)
	if len(keys) != 1 || keys[0] != "EMAIL_HOST" {
		t.Errorf("keys naming hidden hosts = %v, want [EMAIL_HOST]", keys)
	}
}

// A host:port secret is still the stored value, and the handle is the key name.
func TestSecretKeyNamesHostPortValue(t *testing.T) {
	secrets := map[string]string{"REDIS_URL": "cache.internal:6379"}
	hosts := hostsFromSecrets(secrets)
	if len(hosts) != 1 || hosts[0] != "cache.internal" {
		t.Fatalf("hosts = %v, want [cache.internal]", hosts)
	}
	keys := secretKeysNamingHosts(hosts, secrets)
	if len(keys) != 1 || keys[0] != "REDIS_URL" {
		t.Errorf("keys = %v, want [REDIS_URL]", keys)
	}
}

// Hosts inside a URL are never the stored value, so they stay visible.
func TestUrlHostIsNotTreatedAsTheValue(t *testing.T) {
	secrets := map[string]string{"DATABASE_URL": "postgres://user:pass@db.internal/app"}
	hosts := hostsFromSecrets(secrets)
	if _, hidden := splitSecretHosts(hosts, secrets); len(hidden) != 0 {
		t.Errorf("hidden = %v, want none", hidden)
	}
}
