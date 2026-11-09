package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/gateway"
	"github.com/The-17/agentsecrets/pkg/keychainauth"
	"github.com/The-17/agentsecrets/pkg/ui"
)

// identityFetchTimeout bounds the resolver round trip so an unreachable resolver
// degrades doctor quickly instead of hanging a local diagnostic command.
const identityFetchTimeout = 5 * time.Second

// doctorIdentity is the "who am I / where did my token come from / what can I do"
// answer the v4 plan requires doctor to give in one output. It is metadata only:
// it never holds a secret value or even a secret key name.
type doctorIdentity struct {
	Mode         string `json:"mode"`
	SelectedBy   string `json:"selected_by"`
	TokenSource  string `json:"token_source"`
	TokenPresent bool   `json:"token_present"`

	// Local-mode identity (signed-in account).
	Account string `json:"account,omitempty"`

	// Resolver-reported identity, present only in cloud mode with a reachable
	// resolver and a workload token.
	ResolverReached   bool     `json:"resolver_reached"`
	IdentityLevel     string   `json:"identity_level,omitempty"`
	WorkspaceID       string   `json:"workspace_id,omitempty"`
	ProjectID         string   `json:"project_id,omitempty"`
	WorkspaceWide     bool     `json:"workspace_wide,omitempty"`
	Environment       string   `json:"environment,omitempty"`
	TokenID           string   `json:"token_id,omitempty"`
	AgentID           string   `json:"agent_id,omitempty"`
	Scopes            []string `json:"scopes,omitempty"`
	AgentScopes       []string `json:"agent_scopes,omitempty"`
	Attenuated        []string `json:"attenuated,omitempty"`
	AllowedDomains    []string `json:"allowed_domains,omitempty"`
	CanDo             []string `json:"can_do,omitempty"`
	UnavailableReason string   `json:"unavailable_reason,omitempty"`
}

// collectDoctorIdentity answers the three identity questions. It NEVER returns
// an error: a resolver outage, a missing token, or a bad mode are all recorded as
// data so doctor stays usable offline. fetch is injected so tests can drive every
// branch without a network.
func collectDoctorIdentity(fetch func(context.Context, string, string) (*api.WorkloadIdentity, error)) doctorIdentity {
	id := doctorIdentity{
		TokenSource: gateway.DescribeTokenSource(),
	}
	id.TokenPresent = id.TokenSource != "none"

	sel, selErr := gateway.Select("")
	if selErr != nil {
		id.Mode = "unknown"
		id.SelectedBy = "error: " + selErr.Error()
		id.UnavailableReason = "could not determine credential mode: " + selErr.Error()
		return id
	}
	id.Mode = string(sel.Mode)
	id.SelectedBy = sel.Source

	if sel.Mode == gateway.ModeLocal {
		id.Account = config.GetEmail()
		id.UnavailableReason = "local mode: secrets come from the OS keychain, no cloud workload token is in use"
		return id
	}

	if !id.TokenPresent {
		id.UnavailableReason = "cloud mode is active but no workload token was found; set " + gateway.WorkloadTokenEnv
		return id
	}

	ctx, cancel := context.WithTimeout(context.Background(), identityFetchTimeout)
	defer cancel()
	tok := gateway.TokenFromEnv()
	remote, err := fetch(ctx, gateway.ResolverURL(), tok)
	if err != nil {
		id.UnavailableReason = "resolver identity unavailable: " + err.Error()
		return id
	}

	id.ResolverReached = true
	id.IdentityLevel = remote.IdentityLevel
	id.WorkspaceID = remote.WorkspaceID
	id.ProjectID = remote.ProjectID
	id.WorkspaceWide = remote.WorkspaceWide
	id.Environment = remote.Environment
	id.TokenID = remote.TokenID
	id.AgentID = remote.AgentID
	id.Scopes = remote.Scopes
	id.AgentScopes = remote.AgentScopes
	id.Attenuated = remote.Attenuated
	id.AllowedDomains = remote.AllowedDomains
	id.CanDo = remote.CanDo
	return id
}

// appendIdentityFinding surfaces a degraded resolver as a warning, not a broken
// invariant: an unreachable resolver must never mark the whole installation
// unhealthy or make doctor exit non-zero.
func appendIdentityFinding(report *keychainauth.Report, id doctorIdentity) {
	if id.Mode == string(gateway.ModeCloud) && id.TokenPresent && !id.ResolverReached {
		report.Findings = append(report.Findings, keychainauth.Finding{
			ID:     "identity-resolver",
			Title:  "Cloud identity could not be read",
			Status: keychainauth.StatusWarn,
			Detail: id.UnavailableReason,
			Remedy: "Check network access to the resolver; local secret access is unaffected.",
		})
	}
}

// renderIdentitySection prints the identity answer as its own doctor section.
func renderIdentitySection(id doctorIdentity) {
	fmt.Println()
	ui.Divider()
	ui.StatusRow("Mode", fmt.Sprintf("%s (via %s)", id.Mode, id.SelectedBy))
	ui.StatusRow("Token source", id.TokenSource)
	if id.Account != "" {
		ui.StatusRow("Account", id.Account)
	}

	if !id.ResolverReached {
		fmt.Println(ui.DimStyle.Render("    " + id.UnavailableReason))
		return
	}

	project := id.ProjectID
	if id.WorkspaceWide || project == "" {
		project = "workspace-wide (all projects)"
	}
	ui.StatusRow("Workspace", id.WorkspaceID)
	ui.StatusRow("Project", project)
	ui.StatusRow("Environment", id.Environment)
	ui.StatusRow("Token / Agent", fmt.Sprintf("%s / %s (%s)", id.TokenID, id.AgentID, id.IdentityLevel))
	scopes := "none - the resolver will refuse every call"
	if len(id.Scopes) > 0 {
		scopes = strings.Join(id.Scopes, ", ")
	}
	ui.StatusRow("Effective scopes", scopes)

	if len(id.CanDo) > 0 {
		fmt.Println(ui.DimStyle.Render("    What this token can do:"))
		for _, line := range id.CanDo {
			fmt.Println(ui.DimStyle.Render("      - " + line))
		}
	}
	if len(id.Attenuated) > 0 {
		fmt.Println(ui.DimStyle.Render("    Removed from this token (agent has them): " + strings.Join(id.Attenuated, ", ")))
	}
	if len(id.AllowedDomains) > 0 {
		fmt.Println(ui.DimStyle.Render("    Egress allowlist: " + strings.Join(id.AllowedDomains, ", ")))
	}
}
