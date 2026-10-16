package capabilities

import (
	"strings"
)

// PolicyRule defines domain-specific method mappings.
type PolicyRule struct {
	Domain  string            `json:"domain"`
	Methods map[string]Action `json:"methods,omitempty"` // HTTP method → action
}

// SecretPolicy defines policy rules for a single secret.
type SecretPolicy struct {
	Domains []string          `json:"domains,omitempty"` // allowed target domains (legacy)
	Methods map[string]Action `json:"methods,omitempty"` // HTTP method → action (legacy)
	Rules   []PolicyRule      `json:"rules,omitempty"`   // domain-specific rules (v3)
}

type Action string

const (
	Allow             Action = "allow"
	Deny              Action = "deny"
	RequestPermission Action = "request_permission"
)

// AgentCapabilities defines which secrets an agent can access.
type AgentCapabilities struct {
	AllowedSecrets []string `json:"allowed_secrets,omitempty"`
	DeniedSecrets  []string `json:"denied_secrets,omitempty"`
	// Scopes. Pointers so "unset" (nil) is omitted from PUT payloads: the server
	// merges non-None fields, so omitting one leaves the existing value intact.
	// nil = leave unchanged; &true = grant; &false = revoke.
	CanEnvRead      *bool `json:"can_env_read,omitempty"`
	CanProxyResolve *bool `json:"can_proxy_resolve,omitempty"`
}

// EvaluateSecret checks if a secret can be used for the given domain+method.
// Returns Allow if policy is empty (unconstrained).
func EvaluateSecret(c *SecretPolicy, domain, method string) Action {
	if c == nil {
		return Allow // no policy = unrestricted
	}

	// 1. Check domain-specific Rules if present
	var matchedRule *PolicyRule
	if len(c.Rules) > 0 {
		for i := range c.Rules {
			if strings.EqualFold(c.Rules[i].Domain, domain) {
				matchedRule = &c.Rules[i]
				break
			}
		}
	}

	if matchedRule != nil {
		// Domain matched! Now check method inside this rule
		if len(matchedRule.Methods) > 0 {
			action, exists := matchedRule.Methods[strings.ToUpper(method)]
			if exists {
				return action
			}
		}
		// If the method is not explicitly in the specific rule, fall back to global methods if configured
		if len(c.Methods) > 0 {
			globalAction, globalExists := c.Methods[strings.ToUpper(method)]
			if globalExists {
				return globalAction
			}
		}
		return Allow // default to Allow for unlisted methods
	}

	// 2. No domain-specific rule matched. Fall back to global constraints.

	// If there are domain-specific rules, but no global constraints are configured:
	// any unlisted domain is denied.
	if len(c.Rules) > 0 && len(c.Domains) == 0 && len(c.Methods) == 0 {
		return Deny
	}

	// Global Domain check
	if len(c.Domains) > 0 {
		matched := false
		for _, d := range c.Domains {
			if strings.EqualFold(d, domain) {
				matched = true
				break
			}
		}
		if !matched {
			return Deny // domain not allowed globally
		}
	}

	// Global Method check
	if len(c.Methods) > 0 {
		action, exists := c.Methods[strings.ToUpper(method)]
		if exists {
			return action
		}
		return Allow // default to Allow for unlisted methods
	}

	return Allow
}
