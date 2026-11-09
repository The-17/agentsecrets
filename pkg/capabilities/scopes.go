package capabilities

import (
	"fmt"
	"strings"
)

// Scope identifiers the control plane can mint today. The resolver honors a
// wider vocabulary (secrets:read, secrets:admin), but the control plane does
// not mint those yet, so accepting them here would silently no-op and the
// caller would believe it was granted a capability it was not. Fail closed.
const (
	ScopeEnvRead      = "secrets:env"
	ScopeProxyResolve = "secrets:proxy"
)

// SupportedGrantableScopes is the allowlist printed to users on failure so the
// error names the capabilities that actually work rather than the ones they
// asked for.
var SupportedGrantableScopes = []string{ScopeEnvRead, ScopeProxyResolve}

// ParseScopes maps a user-supplied scope list (from --allow) into the control
// plane's capability booleans. It fails closed on any scope the control plane
// cannot grant, returning a message that names what IS supported. An empty list
// returns nil, which lets the server apply its default (proxy-only) — the same
// behavior as omitting all scope flags.
//
// Input is tolerated in several shapes: a single flag
// (--allow secrets:env,secrets:proxy), repeatable flags, or space-separated
// tokens. Everything is lowercased and de-duplicated before matching.
func ParseScopes(raw []string) (*AgentCapabilities, error) {
	var caps AgentCapabilities
	seen := make(map[string]bool)
	any := false

	for _, item := range raw {
		// StringSliceVar already splits on commas; this also permits spaces
		// and tabs in case a shell passes a quoted list.
		for _, tok := range strings.FieldsFunc(item, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\n' || r == '\t'
		}) {
			s := strings.TrimSpace(strings.ToLower(tok))
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			any = true

			switch s {
			case ScopeEnvRead:
				v := true
				caps.CanEnvRead = &v
			case ScopeProxyResolve:
				v := true
				caps.CanProxyResolve = &v
			default:
				return nil, fmt.Errorf("scope %q is not grantable here; the control plane can mint only: %s",
					s, strings.Join(SupportedGrantableScopes, ", "))
			}
		}
	}

	if !any {
		return nil, nil
	}
	return &caps, nil
}
