package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/keyring"
)

// TestChangePasswordRejectedForOpaqueAccount proves the CLI surfaces the
// server's password_login_disabled code when an OPAQUE-enrolled account tries
// to change its password, so the command can point the user at recovery instead
// of reporting a generic failure.
func TestChangePasswordRejectedForOpaqueAccount(t *testing.T) {
	setupAuthTest(t)
	const email = "opaque-change@example.com"

	privateKey, publicKey, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := config.SetEmail(email); err != nil {
		t.Fatal(err)
	}
	if err := config.SetUserID("user-opaque"); err != nil {
		t.Fatal(err)
	}
	if err := keyring.StoreKeypair(email, privateKey, publicKey); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/vault":
			// No vault: skip the local rewrap and reach the server call.
			w.WriteHeader(http.StatusNotFound)
		case "/auth/change-password/":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"code":"password_login_disabled","message":"Password change is disabled for this account. Re-enroll via OPAQUE recovery."}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := api.NewClient(func() string { return config.GetAccessToken() })
	client.BaseURL = server.URL
	svc := NewService(client)

	err = svc.ChangePassword("current-password", "new-password-123")
	if err == nil {
		t.Fatal("ChangePassword succeeded for an OPAQUE-enrolled account")
	}
	if got := errors.FromError(err).Code; got != errors.ErrOPAQUEPasswordDisabled {
		t.Fatalf("error code %q, want %q", got, errors.ErrOPAQUEPasswordDisabled)
	}
}
