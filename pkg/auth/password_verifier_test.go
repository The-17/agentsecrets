package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keychainauth"
)

func TestPasswordVerifierRoundTrip(t *testing.T) {
	keychainauth.SetupTestStub()
	t.Cleanup(keychainauth.TeardownTestStub)

	if err := StorePasswordVerifier("correct horse battery staple"); err != nil {
		t.Fatalf("StorePasswordVerifier: %v", err)
	}
	if !HasPasswordVerifier() {
		t.Fatal("HasPasswordVerifier is false after storing a verifier")
	}
	ok, err := VerifyPasswordLocally("correct horse battery staple")
	if err != nil {
		t.Fatalf("VerifyPasswordLocally: %v", err)
	}
	if !ok {
		t.Fatal("the stored password did not verify")
	}
	ok, err = VerifyPasswordLocally("wrong password")
	if err != nil {
		t.Fatalf("VerifyPasswordLocally with a wrong password: %v", err)
	}
	if ok {
		t.Fatal("a wrong password verified")
	}
}

// TestVerifierIgnoresConfigHash proves that editing config.json cannot satisfy
// the local gate. The old code accepted a SHA-256 verifier read from that file.
func TestVerifierIgnoresConfigHash(t *testing.T) {
	keychainauth.SetupTestStub()
	t.Cleanup(keychainauth.TeardownTestStub)

	tmpHome := t.TempDir()
	oldHome := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return tmpHome, nil }
	t.Cleanup(func() { config.HomeDirHook = oldHome })
	if err := config.InitGlobalConfig(); err != nil {
		t.Fatal(err)
	}
	paths, err := config.GetPaths()
	if err != nil {
		t.Fatal(err)
	}
	forged := `{"email":"user@example.com","password_hash":"0000000000000000000000000000000000000000000000000000000000000000"}`
	if err := os.WriteFile(paths.ConfigFile, []byte(forged), 0600); err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyPasswordLocally("anything")
	if err == nil && ok {
		t.Fatal("a verifier in config.json passed the local gate")
	}
	if ok {
		t.Fatal("the gate verified with no keychain record")
	}
}

func TestLegacyPasswordHashIsPurgedFromConfig(t *testing.T) {
	tmpHome := t.TempDir()
	oldHome := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return tmpHome, nil }
	t.Cleanup(func() { config.HomeDirHook = oldHome })
	if err := config.InitGlobalConfig(); err != nil {
		t.Fatal(err)
	}
	paths, err := config.GetPaths()
	if err != nil {
		t.Fatal(err)
	}
	legacy := `{"email":"user@example.com","password_hash":"deadbeef"}`
	if err := os.WriteFile(filepath.Join(paths.GlobalDir, "config.json"), []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := config.LoadGlobalConfig(); err != nil {
		t.Fatalf("LoadGlobalConfig: %v", err)
	}
	data, err := os.ReadFile(paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "password_hash") {
		t.Fatalf("legacy password hash survived: %s", data)
	}
}
