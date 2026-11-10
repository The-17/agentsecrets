package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apperrors "github.com/The-17/agentsecrets/pkg/errors"
)

// These tests pin the user-facing contract for an expired session. The client
// already attempts the automatic refresh on a 401, so the message must state the
// real outcome definitively: either "it could not be renewed because <reason>"
// (login required) or, when no refresh was attempted, "your session expired".
// Hedged wording like "your session may have expired" is what we're removing.

func new401Server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"message": "Unauthorized"})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCallCtx_RefreshFailure_NoRefreshToken_DefinitiveMessage(t *testing.T) {
	srv := new401Server(t)
	client := NewClientWithURL(srv.URL, func() string { return "stale-access-token" })
	client.SetRefreshTokenCallback(func() (string, error) {
		return "", errors.New("no refresh token available")
	})

	_, err := client.Call("workspaces.list", "GET", nil, nil, nil)
	if err == nil {
		t.Fatal("expected an error when the session cannot be renewed")
	}
	if code := apperrors.FromError(err).Code; code != apperrors.ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %q", code)
	}

	msg := err.Error()
	if !strings.Contains(msg, "no refresh token is stored on this machine") {
		t.Errorf("message should name the missing refresh token, got: %s", msg)
	}
	if !strings.Contains(msg, "Run 'agentsecrets login'") {
		t.Errorf("message should tell the user to log in, got: %s", msg)
	}
	if strings.Contains(msg, "may have expired") {
		t.Errorf("message must not hedge about expiry, got: %s", msg)
	}
}

func TestCallCtx_RefreshFailure_RejectedRefreshToken_DefinitiveMessage(t *testing.T) {
	srv := new401Server(t)
	client := NewClientWithURL(srv.URL, func() string { return "stale-access-token" })
	client.SetRefreshTokenCallback(func() (string, error) {
		return "", errors.New("refresh token expired")
	})

	_, err := client.Call("workspaces.list", "GET", nil, nil, nil)
	if err == nil {
		t.Fatal("expected an error when the session cannot be renewed")
	}
	if code := apperrors.FromError(err).Code; code != apperrors.ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %q", code)
	}

	msg := err.Error()
	if !strings.Contains(msg, "the stored refresh token is expired or no longer valid") {
		t.Errorf("message should name the rejected refresh token, got: %s", msg)
	}
	if !strings.Contains(msg, "Run 'agentsecrets login'") {
		t.Errorf("message should tell the user to log in, got: %s", msg)
	}
}

func TestDecodeError_401WithoutRefresh_DefinitiveLoginMessage(t *testing.T) {
	// When no refresh callback is wired (or the endpoint is public), the client
	// returns the 401 response and the caller decodes it. That path cannot renew
	// itself, so it must say so plainly rather than asking the user to guess.
	srv := new401Server(t)
	client := NewClientWithURL(srv.URL, func() string { return "token" })

	resp, err := client.Call("workspaces.list", "GET", nil, nil, nil)
	if err != nil {
		t.Fatalf("Call returned an unexpected error: %v", err)
	}
	err = client.DecodeError(resp)
	if err == nil {
		t.Fatal("expected DecodeError to classify the 401")
	}
	if code := apperrors.FromError(err).Code; code != apperrors.ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %q", code)
	}

	msg := err.Error()
	if !strings.Contains(msg, "Your session expired. Run 'agentsecrets login'") {
		t.Errorf("message should be definitive about logging in, got: %s", msg)
	}
	if strings.Contains(msg, "may have expired") {
		t.Errorf("message must not hedge about expiry, got: %s", msg)
	}
}
