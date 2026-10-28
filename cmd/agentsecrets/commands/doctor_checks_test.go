package commands

import (
	stderrors "errors"
	"testing"

	"github.com/The-17/agentsecrets/pkg/errors"
)

func TestClassifyAPICall(t *testing.T) {
	if kind, _ := classifyAPICall(nil); kind != "ok" {
		t.Fatalf("nil error should classify ok, got %q", kind)
	}

	for _, code := range []errors.ErrorCode{
		errors.ErrUnauthorized, errors.ErrInvalidCredentials, errors.ErrForbidden,
	} {
		if kind, _ := classifyAPICall(errors.New(code, "x", errors.New(code, "x", nil))); kind != "auth" {
			t.Errorf("code %s classified as %q, want auth", code, kind)
		}
	}

	for _, code := range []errors.ErrorCode{
		errors.ErrConnection, errors.ErrConnectionTimeout,
	} {
		if kind, _ := classifyAPICall(errors.New(code, "x", errors.New(code, "x", nil))); kind != "network" {
			t.Errorf("code %s classified as %q, want network", code, kind)
		}
	}

	if kind, _ := classifyAPICall(errors.New(errors.ErrServerInternal, "x", errors.New(errors.ErrServerInternal, "x", nil))); kind != "other" {
		t.Errorf("internal error classified as %q, want other", kind)
	}
	if kind, _ := classifyAPICall(errors.New(errors.ErrUnknown, "x", stderrors.New("boom"))); kind != "other" {
		t.Errorf("unknown error classified as %q, want other", kind)
	}
}

func TestIsStandardEnvironment(t *testing.T) {
	for _, e := range []string{"development", "staging", "production"} {
		if !isStandardEnvironment(e) {
			t.Errorf("%q should be standard", e)
		}
	}
	for _, e := range []string{"", "prod-eu", "dev"} {
		if isStandardEnvironment(e) {
			t.Errorf("%q should not be standard", e)
		}
	}
}

var _ = stderrors.As
var _ = stderrors.Is
