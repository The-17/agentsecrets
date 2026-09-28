// Package agents handles agent identity registration, token issuance, and lifecycle management.
package agents

import (
	"fmt"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/capabilities"
	"github.com/The-17/agentsecrets/pkg/projects"
)

// Agent represents a registered agent identity.
type Agent struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	WorkspaceID string     `json:"workspace_id"`
	ProjectID   *string    `json:"project_id,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	TokenCount  int        `json:"token_count"`
	LastUsed    *time.Time `json:"last_used_at"`
}

// Token represents a token issued to an agent.
type Token struct {
	ID               string     `json:"id"`
	AgentID          string     `json:"agent_id"`
	Label            string     `json:"label"`
	CreatedAt        time.Time  `json:"created_at"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	LastUsed         *time.Time `json:"last_used_at,omitempty"`
	Status           string     `json:"status"` // e.g., "active", "superseded_overlap", "revoked", "expired"
	RotationState    string     `json:"rotation_state,omitempty"` // active | superseded | revoked
	RotationFamilyID string     `json:"rotation_family_id,omitempty"`
	OverlapUntil     *time.Time `json:"overlap_until,omitempty"`
	NextRotationAt   *time.Time `json:"next_rotation_at,omitempty"`
	RotationPeriodDays *int     `json:"rotation_period_days,omitempty"`
}

// RegisterRequest holds data to register a new agent.
type RegisterRequest struct {
	Name        string `json:"name"`
	WorkspaceID string `json:"-"` // used for routing, not sent in body
	ProjectID   string `json:"project_id,omitempty"`
	Environment string `json:"environment,omitempty"` // development, staging, production
	Label       string `json:"label,omitempty"`
	ExpiresIn   string `json:"expires_in,omitempty"` // e.g., "30d"
}

// RegisterResponse is returned when registering a new agent (contains the cleartext token).
type RegisterResponse struct {
	Agent     Agent      `json:"agent"`
	Token     string     `json:"token"` // The cleartext token (only shown once)
	Label     string     `json:"label,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// IssueTokenRequest holds data to issue a new token.
type IssueTokenRequest struct {
	Environment string `json:"environment,omitempty"`
	Label       string `json:"label,omitempty"`
	ExpiresIn   string `json:"expires_in,omitempty"`
}

// IssueTokenResponse is returned when issuing a new token.
type IssueTokenResponse struct {
	TokenID   string     `json:"token_id"`
	Token     string     `json:"token"` // The cleartext token
	Label     string     `json:"label,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// RotationMetadata mirrors the control plane's rotation block.
type RotationMetadata struct {
	State         string `json:"rotation_state"`
	FamilyID      string `json:"rotation_family_id,omitempty"`
	OverlapUntil  string `json:"overlap_until,omitempty"`
	NextRotation  string `json:"next_rotation_at,omitempty"`
	PeriodDays    *int   `json:"rotation_period_days,omitempty"`
	SupersededBy  string `json:"superseded_by,omitempty"`
	Due           bool   `json:"rotation_due"`
}

// RotateTokenRequest holds data to rotate a token (Axis A).
type RotateTokenRequest struct {
	OverlapHours *int   `json:"overlap_hours,omitempty"`
	Reason       string `json:"reason,omitempty"` // routine | compromise
}

// RotateTokenResponse is returned when rotating a token (cleartext shown once).
type RotateTokenResponse struct {
	Token     string           `json:"token"`
	TokenID   string           `json:"token_id"`
	Label     string           `json:"label,omitempty"`
	ExpiresAt *time.Time       `json:"expires_at,omitempty"`
	Rotation  RotationMetadata `json:"rotation"`
}

// RotationPolicyRequest arms or disarms a rotation cadence (desired-state;
// execution is Pro-gated in the resolver).
type RotationPolicyRequest struct {
	PeriodDays   *int `json:"period_days,omitempty"`
	OverlapHours *int `json:"overlap_hours,omitempty"`
	Enabled      bool `json:"enabled"`
}

// RotationPolicyResponse echoes the armed cadence.
type RotationPolicyResponse struct {
	ID       string           `json:"id"`
	Rotation RotationMetadata `json:"rotation"`
}

// Service provides methods to interact with agent resources.
type Service struct {
	client *api.Client
}

func NewService(client *api.Client) *Service {
	return &Service{client: client}
}

// Register registers a new agent and issues its first token.
// req.WorkspaceID is required; set req.ProjectID to scope the agent to a project.
func (s *Service) Register(req RegisterRequest) (*RegisterResponse, error) {
	if req.WorkspaceID == "" {
		return nil, fmt.Errorf("WorkspaceID is required to register an agent")
	}

	endpointKey := "agents.register"
	urlParams := map[string]string{"workspace_id": req.WorkspaceID}
	if req.ProjectID != "" {
		endpointKey = "agents.register_project"
		urlParams["project_id"] = req.ProjectID
	}

	resp, err := api.CallJSON[RegisterResponse](s.client, endpointKey, "POST", req, urlParams, nil)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// List returns agents scoped to the given workspace (or project if projectID is non-empty).
func (s *Service) List(workspaceID, projectID string) ([]Agent, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("workspaceID is required to list agents")
	}

	endpointKey := "agents.list"
	urlParams := map[string]string{"workspace_id": workspaceID}
	if projectID != "" {
		endpointKey = "agents.list_project"
		urlParams["project_id"] = projectID
	}

	return api.CallJSON[[]Agent](s.client, endpointKey, "GET", nil, urlParams, nil)
}

// ListAll returns all agents in the workspace, including project-scoped ones.
func (s *Service) ListAll(workspaceID string) ([]Agent, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("workspaceID is required to list agents")
	}

	endpointKey := "agents.list"
	urlParams := map[string]string{"workspace_id": workspaceID}
	queryParams := map[string]string{"include_projects": "true"}

	return api.CallJSON[[]Agent](s.client, endpointKey, "GET", nil, urlParams, queryParams)
}

// GetByName returns an agent by its exact name within the given workspace.
// It searches both workspace-scoped agents and all project-scoped agents.
func (s *Service) GetByName(workspaceID, name string) (*Agent, error) {
	// Try single fast request first
	agentsList, err := s.ListAll(workspaceID)
	if err == nil {
		for _, a := range agentsList {
			if a.Name == name {
				return &a, nil
			}
		}
	} else {
		// Fallback to sequential lookups if backend doesn't support ListAll (include_projects)
		// 1. Check workspace-scoped agents
		agentsList, err = s.List(workspaceID, "")
		if err == nil {
			for _, a := range agentsList {
				if a.Name == name {
					return &a, nil
				}
			}
		}

		// 2. Check project-scoped agents
		projService := projects.NewService(s.client)
		projectsList, err := projService.List()
		if err == nil {
			for _, p := range projectsList {
				if p.WorkspaceID == workspaceID {
					projAgents, err := s.List(workspaceID, p.ID)
					if err == nil {
						for _, a := range projAgents {
							if a.Name == name {
								return &a, nil
							}
						}
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("agent '%s' not found in this workspace", name)
}

// TokenIssue issues a new token for an existing agent.
func (s *Service) TokenIssue(workspaceID, registrationID string, req IssueTokenRequest) (*IssueTokenResponse, error) {
	resp, err := api.CallJSON[IssueTokenResponse](s.client, "agents.token_issue", "POST", req, map[string]string{
		"workspace_id":    workspaceID,
		"registration_id": registrationID,
	}, nil)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// TokenList lists all tokens for an agent.
func (s *Service) TokenList(workspaceID, registrationID string) ([]Token, error) {
	return api.CallJSON[[]Token](s.client, "agents.token_list", "GET", nil, map[string]string{
		"workspace_id":    workspaceID,
		"registration_id": registrationID,
	}, nil)
}

// TokenRevoke revokes a single token.
func (s *Service) TokenRevoke(workspaceID, registrationID string, tokenID string) error {
	return s.client.CallNoContent("agents.token_revoke", "DELETE", nil, map[string]string{
		"workspace_id":    workspaceID,
		"registration_id": registrationID,
		"token_id":        tokenID,
	}, nil)
}

// TokenRotate rotates a token: mints a successor in the same family with an
// overlap window (routine) or immediate revocation (compromise). The raw
// successor is returned exactly once and must be persisted by the caller.
func (s *Service) TokenRotate(workspaceID, registrationID, tokenID string, req RotateTokenRequest) (*RotateTokenResponse, error) {
	resp, err := api.CallJSON[RotateTokenResponse](s.client, "agents.token_rotate", "POST", req, map[string]string{
		"workspace_id":    workspaceID,
		"registration_id": registrationID,
		"token_id":        tokenID,
	}, nil)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// TokenRotationSet arms (or with Enabled=false, disarms) a rotation cadence.
func (s *Service) TokenRotationSet(workspaceID, registrationID, tokenID string, req RotationPolicyRequest) (*RotationPolicyResponse, error) {
	resp, err := api.CallJSON[RotationPolicyResponse](s.client, "agents.token_rotation_policy", "PUT", req, map[string]string{
		"workspace_id":    workspaceID,
		"registration_id": registrationID,
		"token_id":        tokenID,
	}, nil)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// TokenRevokeAll revokes all active tokens for an agent by listing then deleting each.
func (s *Service) TokenRevokeAll(workspaceID, registrationID string) error {
	tokens, err := s.TokenList(workspaceID, registrationID)
	if err != nil {
		return err
	}
	for _, t := range tokens {
		if t.Status == "active" {
			if err = s.TokenRevoke(workspaceID, registrationID, t.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// Delete revokes all tokens for an agent then deletes the registration.
// This first revokes all active tokens then issues a DELETE to the workspace agent route.
func (s *Service) Delete(workspaceID, registrationID string) error {
	if workspaceID == "" {
		return fmt.Errorf("workspaceID is required to delete an agent")
	}

	if err := s.TokenRevokeAll(workspaceID, registrationID); err != nil {
		return fmt.Errorf("failed to revoke tokens before delete: %w", err)
	}

	return s.client.CallNoContent("agents.delete", "DELETE", nil, map[string]string{
		"workspace_id":    workspaceID,
		"registration_id": registrationID,
	}, nil)
}

// GetCapabilities retrieves the agent's capabilities restrictions.
func (s *Service) GetCapabilities(workspaceID, registrationID string) (*capabilities.AgentCapabilities, error) {
	resp, err := api.CallJSON[capabilities.AgentCapabilities](s.client, "agents.get_capabilities", "GET", nil, map[string]string{
		"workspace_id":    workspaceID,
		"registration_id": registrationID,
	}, nil)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// SetCapabilities updates the agent's capabilities restrictions.
func (s *Service) SetCapabilities(workspaceID, registrationID string, caps capabilities.AgentCapabilities) (*capabilities.AgentCapabilities, error) {
	resp, err := api.CallJSON[capabilities.AgentCapabilities](s.client, "agents.set_capabilities", "PUT", caps, map[string]string{
		"workspace_id":    workspaceID,
		"registration_id": registrationID,
	}, nil)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
