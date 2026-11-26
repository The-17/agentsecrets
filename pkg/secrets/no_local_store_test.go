package secrets

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
)

// TestListDoesNotWriteALocalSecretCache pins the storage rule: keychain-auth is
// the only local store. List used to persist encrypted values and metadata to
// cloud_cache_<project>_<env>.json under the global dir.
func TestListDoesNotWriteALocalSecretCache(t *testing.T) {
	withRotationProject(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/secrets/prj-1/" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"key":"API_KEY","value":"ciphertext","updated_at":"2026-11-26T00:00:00Z"}]}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := api.NewClient(func() string { return "test-token" })
	client.BaseURL = server.URL
	svc := NewService(client)

	list, err := svc.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].Key != "API_KEY" {
		t.Fatalf("unexpected list: %+v", list)
	}

	paths, err := config.GetPaths()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(paths.GlobalDir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "cloud_cache_") {
			t.Errorf("List wrote a local secret cache %s; keychain-auth is the only local store", e.Name())
		}
	}
}

// TestLocalEnvironmentsIgnoresASecretCache proves the environment list no
// longer derives names from cloud_cache files.
func TestLocalEnvironmentsIgnoresASecretCache(t *testing.T) {
	tmpHome := t.TempDir()
	oldHome := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return tmpHome, nil }
	t.Cleanup(func() { config.HomeDirHook = oldHome })

	origWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmpProj := t.TempDir()
	if err := os.Chdir(tmpProj); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	if err := config.InitGlobalConfig(); err != nil {
		t.Fatal(err)
	}
	paths, err := config.GetPaths()
	if err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(paths.GlobalDir, "cloud_cache_prj-1_preview.json")
	if err := os.WriteFile(cache, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}

	envs, err := config.LocalEnvironments(tmpProj)
	if err != nil {
		t.Fatalf("LocalEnvironments: %v", err)
	}
	for _, e := range envs {
		if e == "preview" {
			t.Fatalf("LocalEnvironments listed %q from a secret cache; the cache must not be a store", e)
		}
	}
}
