package auth

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
)

// TestOpaqueAgainstLiveServer runs the real client against a running
// AgentSecrets server, end to end: signup, confirm recovery, enroll OPAQUE,
// then log in through the OPAQUE exchange on a simulated fresh device.
//
// It is skipped unless AGENTSECRETS_E2E_SERVER points at the API root, for
// example http://127.0.0.1:8000/api or https://api.agentsecrets.tech/api.
//
// This is the test that proves the Go OPAQUE client and the deployed server
// (Django + the Go sidecar) agree through the real HTTP surface. The unit tests
// in opaque_login_test.go use a mock control plane; this one does not.
func TestOpaqueAgainstLiveServer(t *testing.T) {
	base := os.Getenv("AGENTSECRETS_E2E_SERVER")
	if base == "" {
		t.Skip("set AGENTSECRETS_E2E_SERVER to run the live OPAQUE test")
	}
	setupAuthTest(t)

	client := api.NewClient(func() string { return config.GetAccessToken() })
	client.BaseURL = base
	svc := NewService(client)

	stamp := time.Now().UnixNano()
	email := fmt.Sprintf("e2e-opaque-%d@example.com", stamp)
	const password = "opaque-e2e-password-123"

	signup, err := svc.Signup(SignupRequest{
		FirstName: "E2E",
		LastName:  "Opaque",
		Email:     email,
		Password:  password,
	})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	if signup.RecoveryKey == "" {
		t.Fatal("signup did not return a recovery key; cannot confirm recovery")
	}
	if !svc.ServerSupportsOpaque() {
		t.Fatal("server does not report OPAQUE support; cannot run the live OPAQUE test")
	}

	// Enrollment is gated on a confirmed recovery key.
	if err := svc.ConfirmRecovery(password); err != nil {
		t.Fatalf("ConfirmRecovery: %v", err)
	}

	if err := svc.EnrollOpaque(email, password); err != nil {
		t.Fatalf("EnrollOpaque: %v", err)
	}
	if !config.GetOpaqueEnrolled() {
		t.Fatal("EnrollOpaque did not record the local enrollment flag")
	}

	// Simulate a fresh device: clear the local flag so Login cannot rely on it.
	// The password factor is now disabled server-side, so Login must fall back
	// to the OPAQUE exchange to succeed.
	if err := config.SetOpaqueEnrolled(false); err != nil {
		t.Fatal(err)
	}
	result, err := svc.Login(email, password)
	if err != nil {
		t.Fatalf("Login after enrollment: %v", err)
	}
	if !result.OpaqueAuthenticated {
		t.Fatal("Login did not authenticate through OPAQUE after enrollment")
	}
	if !config.GetOpaqueEnrolled() {
		t.Error("Login did not restore the local enrollment flag after the OPAQUE exchange")
	}
}
