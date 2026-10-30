package errors

import (
	"fmt"
	"os"
	"testing"
)

type mockNetError struct {
	err     string
	timeout bool
}

func (e *mockNetError) Error() string   { return e.err }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return false }

func TestFromError(t *testing.T) {
	// Test nil
	if FromError(nil) != nil {
		t.Error("FromError(nil) should be nil")
	}

	// Test already wrapped CLIError
	original := New(ErrSecretNotFound, "Not found", nil)
	if FromError(original) != original {
		t.Error("FromError should return original CLIError unmodified")
	}

	// A CLIError wrapped with %w must keep its code. Commands add context with
	// fmt.Errorf("migrate export: %w", err); if FromError only type-asserts the
	// top level, every wrapped error degrades to ERR-999 and a clean 401 is
	// reported as "an unexpected error occurred".
	wrappedAuth := fmt.Errorf("migrate export: %w", New(ErrUnauthorized, "Unauthorized", nil))
	if got := FromError(wrappedAuth); got.Code != ErrUnauthorized {
		t.Errorf("FromError(wrapped CLIError) = %s, want %s", got.Code, ErrUnauthorized)
	}

	// Test network timeout
	netTimeErr := FromError(&mockNetError{err: "timeout", timeout: true})
	if netTimeErr.Code != ErrConnectionTimeout {
		t.Errorf("Expected network timeout ErrConnectionTimeout, got %s", netTimeErr.Code)
	}

	// Test general network error
	netErr := FromError(&mockNetError{err: "failed", timeout: false})
	if netErr.Code != ErrConnection {
		t.Errorf("Expected network ErrConnection, got %s", netErr.Code)
	}

	// Test OS permission denied
	permErr := FromError(os.ErrPermission)
	if permErr.Code != ErrPermissionDenied {
		t.Errorf("Expected permission ErrPermissionDenied, got %s", permErr.Code)
	}

	// Test OS file not found
	notExistErr := FromError(os.ErrNotExist)
	if notExistErr.Code != ErrFileNotFound {
		t.Errorf("Expected file not found ErrFileNotFound, got %s", notExistErr.Code)
	}

	// Test fallback/generic error
	genericErr := FromError(fmt.Errorf("random error message"))
	if genericErr.Code != ErrUnknown {
		t.Errorf("Expected fallback ErrUnknown, got %s", genericErr.Code)
	}
}

func TestCLIErrorUnwrap(t *testing.T) {
	innerErr := fmt.Errorf("underlying network failure")
	cliErr := New(ErrConnection, "failed to connect", innerErr)

	if cliErr.Unwrap() != innerErr {
		t.Errorf("Unwrap() = %v, expected %v", cliErr.Unwrap(), innerErr)
	}
}
