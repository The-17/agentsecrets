// Package workspaces handles the orchestration of workspace-related operations.
package workspaces

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/keyring"
)

// Service provides workspace management operations.
type Service struct {
	API *api.Client
}

// NewService creates a new workspaces service.
func NewService(apiClient *api.Client) *Service {
	return &Service{API: apiClient}
}

// Create creates a new team workspace.
func (s *Service) Create(name string) error {
	email := config.GetEmail()
	if email == "" {
		return fmt.Errorf("not logged in")
	}

	wsKey, err := crypto.GenerateWorkspaceKey()
	if err != nil {
		return fmt.Errorf("create workspace: %w", err)
	}

	pubKey, err := keyring.GetPublicKey(email)
	if err != nil {
		return fmt.Errorf("create workspace: public key not found: %w", err)
	}

	encryptedWsKey, err := crypto.EncryptForUser(pubKey, wsKey)
	if err != nil {
		return fmt.Errorf("create workspace: encryption failed: %w", err)
	}

	resp, err := s.API.Call("workspaces.create", "POST", map[string]any{
		"name":                    name,
		"encrypted_workspace_key": b64Enc(encryptedWsKey),
	}, nil)
	if err != nil {
		return fmt.Errorf("create workspace: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return parseAPIError(resp, "create workspace")
	}

	var res struct {
		Data struct {
			ID   string `json:"id"`
			Type string `json:"type"`
			Role string `json:"role"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return fmt.Errorf("create workspace: failed to parse response: %w", err)
	}

	// Load config, defaulting to empty if it doesn't exist yet.
	cfg, err := config.LoadGlobalConfig()
	if err != nil {
		return fmt.Errorf("create workspace: failed to load config: %w", err)
	}
	if cfg.Workspaces == nil {
		cfg.Workspaces = make(map[string]config.WorkspaceCacheEntry)
	}

	cfg.Workspaces[res.Data.ID] = config.WorkspaceCacheEntry{
		Name: name,
		Key:  b64Enc(wsKey),
		Role: res.Data.Role,
		Type: res.Data.Type,
	}
	cfg.SelectedWorkspaceID = res.Data.ID

	return config.SaveGlobalConfig(cfg)
}

// Invite adds a member to a workspace by encrypting the workspace key for them.
func (s *Service) Invite(workspaceID, email, role string) error {
	// Step 1: fetch the invitee's public key.
	pubKeyResp, err := s.API.Call("users.public_key", "GET", nil, map[string]string{"email": email})
	if err != nil {
		return fmt.Errorf("invite: failed to get public key: %w", err)
	}
	defer pubKeyResp.Body.Close()

	if pubKeyResp.StatusCode != http.StatusOK {
		return parseAPIError(pubKeyResp, "invite (get public key)")
	}

	var pubKeyRes struct {
		Data struct {
			PublicKey string `json:"public_key"`
		} `json:"data"`
	}
	if err := json.NewDecoder(pubKeyResp.Body).Decode(&pubKeyRes); err != nil {
		return fmt.Errorf("invite: failed to parse public key: %w", err)
	}

	recipientPubKey, err := b64Dec(pubKeyRes.Data.PublicKey, "invite: invalid public key in response")
	if err != nil {
		return err
	}

	// Step 2: encrypt the workspace key for the invitee.
	cfg, err := config.LoadGlobalConfig()
	if err != nil {
		return fmt.Errorf("invite: failed to load config: %w", err)
	}

	ws, ok := cfg.Workspaces[workspaceID]
	if !ok {
		return fmt.Errorf("invite: workspace %s not found in cache", workspaceID)
	}

	wsKey, err := b64Dec(ws.Key, "invite: invalid workspace key in cache")
	if err != nil {
		return err
	}

	encryptedForInvitee, err := crypto.EncryptForUser(recipientPubKey, wsKey)
	if err != nil {
		return fmt.Errorf("invite: encryption failed: %w", err)
	}

	// Step 3: send the invite.
	inviteResp, err := s.API.Call("workspaces.invite", "POST", map[string]any{
		"email":                   email,
		"role":                    role,
		"encrypted_workspace_key": b64Enc(encryptedForInvitee),
	}, map[string]string{"workspace_id": workspaceID})
	if err != nil {
		return fmt.Errorf("invite: API call failed: %w", err)
	}
	defer inviteResp.Body.Close()

	if inviteResp.StatusCode != http.StatusCreated && inviteResp.StatusCode != http.StatusOK {
		return parseAPIError(inviteResp, "invite")
	}

	return nil
}

// WorkspaceMember represents a member of a workspace.
type WorkspaceMember struct {
	Email  string `json:"email"`
	Role   string `json:"role"`
	Status string `json:"status"`
}

// Members lists all members of a workspace.
func (s *Service) Members(workspaceID string) ([]WorkspaceMember, error) {
	resp, err := s.API.Call("workspaces.members", "GET", nil, map[string]string{"workspace_id": workspaceID})
	if err != nil {
		return nil, fmt.Errorf("members: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp, "list members")
	}

	var res struct {
		Data []WorkspaceMember `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("members: failed to parse response: %w", err)
	}

	return res.Data, nil
}

// RemoveMember removes a member from a workspace.
func (s *Service) RemoveMember(workspaceID, email string) error {
	resp, err := s.API.Call("workspaces.remove_member", "DELETE", nil, map[string]string{
		"workspace_id": workspaceID,
		"email":        email,
	})
	if err != nil {
		return fmt.Errorf("remove member: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return parseAPIError(resp, "remove member")
	}

	return nil
}


func parseAPIError(resp *http.Response, context string) error {
	var errResp struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil && errResp.Message != "" {
		return fmt.Errorf("%s failed: %s", context, errResp.Message)
	}
	return fmt.Errorf("%s failed: HTTP %d", context, resp.StatusCode)
}

// b64Enc is a shorthand for base64 standard encoding.
func b64Enc(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// b64Dec decodes a base64 string, wrapping any error with the given context message.
func b64Dec(s, context string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", context, err)
	}
	return b, nil
}