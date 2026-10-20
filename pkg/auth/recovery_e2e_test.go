package auth

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
)

// TestRecoveryAgainstLiveServer runs the real client against a running
// AgentSecrets server. It is skipped unless AGENTSECRETS_E2E_SERVER points at
// the API root, for example http://127.0.0.1:8000/api.
//
// This is the only test that proves the Go signer and the Python verifier agree
// through the real HTTP surface, including the vault CAS write.
func TestRecoveryAgainstLiveServer(t *testing.T) {
	base := os.Getenv("AGENTSECRETS_E2E_SERVER")
	if base == "" {
		t.Skip("set AGENTSECRETS_E2E_SERVER to run the live recovery test")
	}
	setupAuthTest(t)

	client := api.NewClient(func() string { return config.GetAccessToken() })
	client.BaseURL = base
	svc := NewService(client)

	stamp := time.Now().UnixNano()
	email := fmt.Sprintf("e2e-recovery-%d@example.com", stamp)
	const (
		oldPassword = "old-password-123"
		newPassword = "new-password-456"
	)

	signup, err := svc.Signup(SignupRequest{
		FirstName: "E2E",
		LastName:  "Recovery",
		Email:     email,
		Password:  oldPassword,
	})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	if !signup.VaultCreated {
		t.Fatal("signup did not create a vault")
	}
	if signup.RecoveryKey == "" {
		t.Fatal("signup did not return a recovery key")
	}

	recovered, err := svc.RecoverAccount(email, signup.RecoveryKey, newPassword)
	if err != nil {
		t.Fatalf("RecoverAccount: %v", err)
	}
	if recovered.VaultVersion != signup.VaultVersion+1 {
		t.Fatalf("vault version %d, want %d", recovered.VaultVersion, signup.VaultVersion+1)
	}

	// The new password must drive a normal login that unlocks the rewrapped
	// vault, and the old password must stop working.
	login, err := svc.PerformLogin(email, newPassword, nil, nil)
	if err != nil {
		t.Fatalf("login with new password: %v", err)
	}
	if login.RecoveryKey != "" {
		t.Fatal("normal login returned a recovery key")
	}
	if login.VaultVersion != recovered.VaultVersion {
		t.Fatalf("login vault version %d, want %d", login.VaultVersion, recovered.VaultVersion)
	}
	if _, err := svc.PerformLogin(email, oldPassword, nil, nil); err == nil {
		t.Fatal("old password still logs in")
	}
}
