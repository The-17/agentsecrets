package proxy

import (
	"fmt"
	"strings"

	"github.com/The-17/agentsecrets/pkg/config"
)

// ExpectedContext is an optional caller-declared context for a credential call.
//
// When set, the engine asserts that the context it actually resolves — from the
// project config bound to the call and the active environment — matches what the
// caller declared. A mismatch fails the call closed: no secret is injected and no
// request leaves the proxy. This turns the agent-token scope check (a Tier-1
// advisory status) into a Tier-2 hard guarantee that the caller opts into by
// declaring its expectation.
//
// Each field is independent: set only what you want asserted. "personal" is a
// valid workspace reference and resolves to the caller's personal workspace, so a
// contract can name workspace:"personal" and stay portable across engineers
// without baking in a display name.
type ExpectedContext struct {
	Workspace   string // workspace name, ID, or "personal"
	Project     string
	Environment string
}

// AssertExpectedContext compares a declared ExpectedContext against the context
// the call actually resolves. It is a pure decision: it resolves the workspace
// reference (so "personal" maps to the concrete ID) and returns a fail-closed
// error on any mismatch. actualWS/actualProj/actualEnv are the resolved context
// (project config + active environment). It returns nil when exp is nil (backward
// compatible) or when every non-empty declared field agrees with reality.
func AssertExpectedContext(exp *ExpectedContext, actualWS, actualProj, actualEnv string) error {
	if exp == nil {
		return nil
	}
	if exp.Workspace != "" {
		id, err := config.ResolveWorkspaceRef(exp.Workspace)
		if err != nil {
			return fmt.Errorf("context assertion failed: %w", err)
		}
		if id != actualWS {
			return fmt.Errorf("context assertion failed: expected workspace %q (resolved %q) but the call is bound to workspace %q", exp.Workspace, id, actualWS)
		}
	}
	if exp.Project != "" && exp.Project != actualProj {
		return fmt.Errorf("context assertion failed: expected project %q but the call is bound to project %q", exp.Project, actualProj)
	}
	if exp.Environment != "" && !strings.EqualFold(exp.Environment, actualEnv) {
		return fmt.Errorf("context assertion failed: expected environment %q but the active environment is %q", exp.Environment, actualEnv)
	}
	return nil
}
