package secrets

import (
	"errors"
	"strings"
	"testing"
)

func TestStoreKeychainBatchSurfacesFailures(t *testing.T) {
	orig := setSecretsBatch
	t.Cleanup(func() { setSecretsBatch = orig })

	setSecretsBatch = func(projectID, environment string, secrets map[string]string, policies map[string][]byte) (int, error) {
		return 0, errors.New("daemon unavailable")
	}

	err := storeKeychainBatch("proj", "development", map[string]string{"A": "1"})
	if err == nil {
		t.Fatal("a keychain failure must not be swallowed")
	}
	if !strings.Contains(err.Error(), "keychain") || !strings.Contains(err.Error(), "daemon unavailable") {
		t.Errorf("error should say the keychain write failed and why, got %v", err)
	}
}

func TestStoreKeychainBatchPassesThrough(t *testing.T) {
	orig := setSecretsBatch
	t.Cleanup(func() { setSecretsBatch = orig })

	var gotProject, gotEnv string
	var gotSecrets map[string]string
	setSecretsBatch = func(projectID, environment string, secrets map[string]string, policies map[string][]byte) (int, error) {
		gotProject, gotEnv, gotSecrets = projectID, environment, secrets
		return len(secrets), nil
	}

	kv := map[string]string{"A": "1", "B": "2"}
	if err := storeKeychainBatch("proj", "staging", kv); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotProject != "proj" || gotEnv != "staging" {
		t.Errorf("got project=%q env=%q, want proj/staging", gotProject, gotEnv)
	}
	if len(gotSecrets) != 2 {
		t.Errorf("got %d secrets, want 2", len(gotSecrets))
	}
}
