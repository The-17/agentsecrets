package commands

import (
	"strings"
	"testing"
)

func TestGuardInjection(t *testing.T) {
	secrets := map[string]string{"A": "1"}

	t.Run("missing --only keys fail even with --allow-empty", func(t *testing.T) {
		err := guardInjection(secrets, []string{"NOPE"}, "development", true)
		if err == nil {
			t.Fatal("expected an error for a key the project does not store")
		}
		if !strings.Contains(err.Error(), "NOPE") {
			t.Errorf("error should name the missing key, got %v", err)
		}
	})

	t.Run("empty project fails closed by default", func(t *testing.T) {
		err := guardInjection(map[string]string{}, nil, "development", false)
		if err == nil {
			t.Fatal("expected the zero-secret state to fail without --allow-empty")
		}
		if !strings.Contains(err.Error(), "allow-empty") {
			t.Errorf("error should name the opt-in, got %v", err)
		}
	})

	t.Run("empty project runs with --allow-empty", func(t *testing.T) {
		if err := guardInjection(map[string]string{}, nil, "development", true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("resolved secrets pass", func(t *testing.T) {
		if err := guardInjection(secrets, nil, "development", false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("active environment produces a usable command", func(t *testing.T) {
		err := guardInjection(secrets, []string{"NOPE"}, "", false)
		if err == nil {
			t.Fatal("expected an error")
		}
		if strings.Contains(err.Error(), "--env the active environment") {
			t.Errorf("suggestion must not interpolate a label as a flag value, got %v", err)
		}
		if !strings.Contains(err.Error(), "not found in the active environment") {
			t.Errorf("error should name the environment, got %v", err)
		}
	})
}
