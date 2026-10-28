package auth

import (
	stdErrors "errors"
	"strings"
	"testing"

	"github.com/The-17/agentsecrets/pkg/errors"
)

// A configured account with no token means the credential store no longer holds
// the session, not that the session was revoked. Saying "invalid, revoked, or
// expired" sent users hunting for a cause that does not exist after a keychain
// replacement.
func TestMissingSessionNamesTheAccount(t *testing.T) {
	err := missingSessionError("testagent@agentsecrets.tech")
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "testagent@agentsecrets.tech") {
		t.Errorf("message does not name the account: %s", msg)
	}
	var cliErr *errors.CLIError
	if !stdErrors.As(err, &cliErr) || cliErr.Code != errors.ErrUnauthorized {
		t.Errorf("expected AUTH-401, got %v", err)
	}
	if strings.Contains(strings.ToLower(msg), "revoked") {
		t.Errorf("message claims the session was revoked: %s", msg)
	}
}

func TestMissingSessionWithoutAnAccountStaysGeneric(t *testing.T) {
	err := missingSessionError("")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "logged in") {
		t.Errorf("unexpected message: %s", err)
	}
}
