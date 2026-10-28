// Package workspaces handles the orchestration of workspace-related operations.
package workspaces

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

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
		"encrypted_workspace_key": crypto.B64Encode(encryptedWsKey),
	}, nil, nil)
	if err != nil {
		return fmt.Errorf("create workspace: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return s.API.DecodeError(resp)
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

	// Load config
	cfg, _ := config.LoadGlobalConfig()
	if cfg == nil {
		cfg = &config.GlobalConfig{}
	}
	if cfg.Workspaces == nil {
		cfg.Workspaces = make(map[string]config.WorkspaceCacheEntry)
	}

	cfg.Workspaces[res.Data.ID] = config.WorkspaceCacheEntry{
		Name: name,
		Key:  crypto.B64Encode(wsKey),
		Role: res.Data.Role,
		Type: res.Data.Type,
	}
	cfg.SelectedWorkspaceID = res.Data.ID

	return config.SaveGlobalConfig(cfg)
}

// Invite adds a member to a workspace by encrypting the workspace key for them.
func (s *Service) Invite(workspaceID, email, role string) error {
	results, err := s.InviteBatch(workspaceID, []string{email}, role)
	if err != nil {
		return err
	}
	if len(results) > 0 && results[0].Error != "" {
		return fmt.Errorf("invite %s: %s", email, results[0].Error)
	}
	return nil
}

// InviteResult holds the per-email outcome of a batch invite.
type InviteResult struct {
	Email string `json:"email"`
	Error string `json:"error,omitempty"`
}

// InviteBatch invites multiple users to a workspace in a single API call.
// It fetches public keys concurrently for performance, encrypts the workspace
// key for each invitee, then sends one bulk request.
func (s *Service) InviteBatch(workspaceID string, emails []string, role string) ([]InviteResult, error) {
	cfg, err := config.LoadGlobalConfig()
	if err != nil {
		return nil, fmt.Errorf("invite batch: load config: %w", err)
	}

	ws, ok := cfg.Workspaces[workspaceID]
	if !ok {
		return nil, fmt.Errorf("invite batch: workspace %s not found", workspaceID)
	}

	// The workspace key lives in the OS keyring. config.json carries metadata
	// only, because StoreWorkspaceCache strips the key out, so reading ws.Key
	// here always produced an empty string. B64Decode accepts "", the CLI then
	// sealed an EMPTY key for the invitee, and the server marked the membership
	// active because the envelope was non-empty. The result was a workspace the
	// invitee could see, select and never decrypt.
	wsKey, err := config.GetWorkspaceKey(workspaceID)
	if err != nil {
		return nil, fmt.Errorf("invite batch: cannot read the key for workspace %q: %w", ws.Name, err)
	}
	if len(wsKey) == 0 {
		return nil, fmt.Errorf("invite batch: the key for workspace %q is empty; refusing to invite with an empty key", ws.Name)
	}
	if err != nil {
		return nil, err
	}

	// Fetch all public keys concurrently
	type keyResult struct {
		email  string
		pubKey []byte
		err    error
	}

	ch := make(chan keyResult, len(emails))
	for _, email := range emails {
		go func(e string) {
			pubKeyResp, err := s.API.Call("users.public_key", "GET", nil, map[string]string{"email": e}, nil)
			if err != nil {
				ch <- keyResult{email: e, err: fmt.Errorf("failed to get public key: %w", err)}
				return
			}
			defer pubKeyResp.Body.Close()

			if pubKeyResp.StatusCode != http.StatusOK {
				ch <- keyResult{email: e, err: fmt.Errorf("user not found or no public key")}
				return
			}

			var res struct {
				Data struct {
					PublicKey string `json:"public_key"`
				} `json:"data"`
			}
			if err := json.NewDecoder(pubKeyResp.Body).Decode(&res); err != nil {
				ch <- keyResult{email: e, err: fmt.Errorf("invalid public key response")}
				return
			}

			pk, err := crypto.B64Decode(res.Data.PublicKey, "invalid public key")
			if err != nil {
				ch <- keyResult{email: e, err: err}
				return
			}

			ch <- keyResult{email: e, pubKey: pk}
		}(email)
	}

	// Collect results and encrypt workspace key for each
	type inviteEntry struct {
		Email                 string `json:"email"`
		Role                  string `json:"role"`
		EncryptedWorkspaceKey string `json:"encrypted_workspace_key"`
	}

	var invites []inviteEntry
	var results []InviteResult

	for range emails {
		kr := <-ch
		if kr.err != nil {
			results = append(results, InviteResult{Email: kr.email, Error: kr.err.Error()})
			continue
		}

		encKey, err := crypto.EncryptForUser(kr.pubKey, wsKey)
		if err != nil {
			results = append(results, InviteResult{Email: kr.email, Error: fmt.Sprintf("encryption failed: %v", err)})
			continue
		}

		invites = append(invites, inviteEntry{
			Email:                 kr.email,
			Role:                  role,
			EncryptedWorkspaceKey: crypto.B64Encode(encKey),
		})
	}

	// If no valid invites, return early with errors
	if len(invites) == 0 {
		return results, nil
	}

	// Send bulk invite
	resp, err := s.API.Call("workspaces.invite", "POST", map[string]any{
		"invites": invites,
	}, map[string]string{"workspace_id": workspaceID}, nil)
	if err != nil {
		return nil, fmt.Errorf("invite batch: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, s.API.DecodeError(resp)
	}

	// Parse per-email results from API
	var apiRes struct {
		Data []InviteResult `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiRes); err == nil && len(apiRes.Data) > 0 {
		results = append(results, apiRes.Data...)
	} else {
		// If the API doesn't return per-email results, mark all as success
		for _, inv := range invites {
			results = append(results, InviteResult{Email: inv.Email})
		}
	}

	return results, nil
}

// WorkspaceMember represents a member of a workspace.
type WorkspaceMember struct {
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Status string `json:"status"`
}

// Members lists all members of a workspace.
func (s *Service) Members(workspaceID string) ([]WorkspaceMember, error) {
	return api.CallJSON[[]WorkspaceMember](s.API, "workspaces.members", "GET", nil, map[string]string{"workspace_id": workspaceID}, nil)
}

// RemoveMember removes a member from a workspace by their user ID.
func (s *Service) RemoveMember(workspaceID, userID string) error {
	return s.API.CallNoContent("workspaces.remove_member", "DELETE", nil, map[string]string{
		"workspace_id": workspaceID,
		"user_id":      userID,
	}, nil)
}

// UpdateRole updates the role of a member in a workspace.
func (s *Service) UpdateRole(workspaceID, userID, action string) error {
	return s.API.CallNoContent("workspaces.role_update", "POST", map[string]string{
		"action": action,
	}, map[string]string{
		"workspace_id": workspaceID,
		"user_id":      userID,
	}, nil)
}

// --- Workspace Allowlist ---

// AddAllowlist adds one or more domains to the workspace allowlist.
func (s *Service) AddAllowlist(workspaceID string, domains ...string) error {
	return s.API.CallNoContent("workspaces.allowlist_add", "POST", map[string]interface{}{
		"domains": domains,
	}, map[string]string{
		"workspace_id": workspaceID,
	}, nil)
}

// RemoveAllowlist removes a domain from the workspace allowlist.
func (s *Service) RemoveAllowlist(workspaceID, domain string) error {
	return s.API.CallNoContent("workspaces.allowlist_remove", "DELETE", nil, map[string]string{
		"workspace_id": workspaceID,
		"domain":       domain,
	}, nil)
}

// AllowlistDomain represents a domain in the workspace allowlist.
type AllowlistDomain struct {
	Domain    string `json:"domain"`
	AddedBy   string `json:"added_by_email"`
	CreatedAt string `json:"created_at"`
}

// ListAllowlist retrieves the allowlist for a workspace.
func (s *Service) ListAllowlist(workspaceID string) ([]AllowlistDomain, error) {
	return api.CallJSON[[]AllowlistDomain](s.API, "workspaces.allowlist_list", "GET", nil, map[string]string{
		"workspace_id": workspaceID,
	}, nil)
}

// AllowlistLogEntry represents an entry in the allowlist audit log.
type AllowlistLogEntry struct {
	CreatedAt string `json:"performed_at"`
	UserEmail string `json:"performed_by_email"`
	Action    string `json:"action"` // ADDED or REMOVED
	Domain    string `json:"domain"`
}

// LogAllowlist retrieves the audit log for the workspace allowlist.
func (s *Service) LogAllowlist(workspaceID string) ([]AllowlistLogEntry, error) {
	return api.CallJSON[[]AllowlistLogEntry](s.API, "workspaces.allowlist_log", "GET", nil, map[string]string{
		"workspace_id": workspaceID,
	}, nil)
}

// Delete deletes a workspace by its ID. A personal workspace can never be
// deleted: it is the account's default namespace. This guard is enforced here
// at the service layer — not only in the CLI command — so no caller (verb-noun
// alias, future API consumer) can bypass it.
func (s *Service) Delete(workspaceID string) error {
	if cfg, err := config.LoadGlobalConfig(); err == nil && cfg != nil {
		if ws, ok := cfg.Workspaces[workspaceID]; ok && strings.EqualFold(ws.Type, "personal") {
			return fmt.Errorf("cannot delete your personal workspace")
		}
	}

	if err := s.API.CallNoContent("workspaces.delete", "DELETE", nil, map[string]string{
		"workspace_id": workspaceID,
	}, nil); err != nil {
		return err
	}

	// Remove it from the local global config if it's cached there
	cfg, err := config.LoadGlobalConfig()
	if err == nil && cfg != nil {
		delete(cfg.Workspaces, workspaceID)
		if cfg.SelectedWorkspaceID == workspaceID {
			cfg.SelectedWorkspaceID = ""
		}
		if err := config.SaveGlobalConfig(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: workspace deleted on cloud but failed to update local config cache: %v\n", err)
		}
	}

	return nil
}
