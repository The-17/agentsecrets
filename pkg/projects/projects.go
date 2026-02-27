package projects

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/keyring"
)

// Project represents a project in a workspace
type Project struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	WorkspaceID string `json:"workspace_id"`
}

// Service handles project orchestration
type Service struct {
	API *api.Client
}

// NewService creates a new project service
func NewService(client *api.Client) *Service {
	return &Service{API: client}
}

// List returns all projects for the currently selected workspace
func (s *Service) List() ([]Project, error) {
	resp, err := s.API.Call("projects.list", "GET", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, s.API.DecodeError(resp)
	}

	var result struct {
		Data []Project `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("list projects: decode: %w", err)
	}

	return result.Data, nil
}

// Create creates a new project in the active workspace and binds it locally
func (s *Service) Create(name, description string) (*Project, error) {
	workspaceID := config.GetSelectedWorkspaceID()
	if workspaceID == "" {
		global, _ := config.LoadGlobalConfig()
		if global != nil {
			for id, ws := range global.Workspaces {
				if workspaceID == "" || ws.Type == "personal" {
					workspaceID = id
				}
				if ws.Type == "personal" {
					break
				}
			}
		}
	}

	if workspaceID == "" {
		return nil, fmt.Errorf("no workspace selected; run 'agentsecrets workspace switch' first")
	}

	data := map[string]interface{}{
		"name":         name,
		"workspace_id": workspaceID,
	}
	if description != "" {
		data["description"] = description
	}

	resp, err := s.API.Call("projects.create", "POST", data, nil)
	if err != nil {
		return nil, fmt.Errorf("create project: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, s.API.DecodeError(resp)
	}

	var result struct {
		Data Project `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("create project: decode: %w", err)
	}

	// Bind locally matching SecretsCLI behavior
	if err := s.bindLocally(&result.Data); err != nil {
		return nil, fmt.Errorf("create project: bind: %w", err)
	}

	return &result.Data, nil
}

// Use selects a project by name and updates the local .agentsecrets/project.json
func (s *Service) Use(name string) (*Project, error) {
	workspaceID := config.GetSelectedWorkspaceID()
	if workspaceID == "" {
		return nil, fmt.Errorf("no workspace selected; run 'agentsecrets workspace switch' first")
	}

	params := map[string]string{
		"workspace_id": workspaceID,
		"project_name": name,
	}

	resp, err := s.API.Call("projects.get", "GET", nil, params)
	if err != nil {
		return nil, fmt.Errorf("use project: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, s.API.DecodeError(resp)
	}

	var result struct {
		Data Project `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("use project: decode: %w", err)
	}

	// Update local config
	if err := s.bindLocally(&result.Data); err != nil {
		return nil, fmt.Errorf("use project: bind: %w", err)
	}

	return &result.Data, nil
}

// bindLocally updates the fields in the existing .agentsecrets/project.json
func (s *Service) bindLocally(project *Project) error {
	projectDir := ".agentsecrets"
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		return fmt.Errorf("failed to create projects directory: %w", err)
	}

	local, _ := config.LoadProjectConfig()
	if local == nil {
		local = &config.ProjectConfig{Environment: "development"}
	}

	local.ProjectID = project.ID
	local.ProjectName = project.Name
	local.Description = project.Description
	local.WorkspaceID = project.WorkspaceID
	
	// Get workspace name from global cache if available
	global, _ := config.LoadGlobalConfig()
	if global != nil {
		if ws, ok := global.Workspaces[project.WorkspaceID]; ok {
			local.WorkspaceName = ws.Name
		}
	}

	return config.SaveProjectConfig(local)
}

// Update modifies an existing project's name or description
func (s *Service) Update(oldName, newName, desc string) error {
	workspaceID := config.GetSelectedWorkspaceID()
	if workspaceID == "" {
		return fmt.Errorf("no workspace selected; run 'agentsecrets workspace switch' first")
	}

	data := make(map[string]interface{})
	if newName != "" {
		data["name"] = newName
	}
	if desc != "" {
		data["description"] = desc
	}

	params := map[string]string{
		"workspace_id": workspaceID,
		"project_name": oldName,
	}

	resp, err := s.API.Call("projects.update", "PATCH", data, params)
	if err != nil {
		return fmt.Errorf("update project: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return s.API.DecodeError(resp)
	}

	// Update local project config if the updated project is the currently active one
	local, err := config.LoadProjectConfig()
	if err == nil && local != nil && local.ProjectName == oldName && local.WorkspaceID == workspaceID {
		if newName != "" {
			local.ProjectName = newName
		}
		if desc != "" {
			local.Description = desc
		}
		_ = config.SaveProjectConfig(local)
	}

	return nil
}

// Delete permanently removes a project from the workspace
func (s *Service) Delete(name string) error {
	workspaceID := config.GetSelectedWorkspaceID()
	if workspaceID == "" {
		return fmt.Errorf("no workspace selected; run 'agentsecrets workspace switch' first")
	}

	params := map[string]string{
		"workspace_id": workspaceID,
		"project_name": name,
	}

	resp, err := s.API.Call("projects.delete", "DELETE", nil, params)
	if err != nil {
		return fmt.Errorf("delete project: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return s.API.DecodeError(resp)
	}

	// Unbind local project info if we just deleted the active one
	local, err := config.LoadProjectConfig()
	if err == nil && local != nil && local.ProjectName == name && local.WorkspaceID == workspaceID {
		os.Remove(".agentsecrets/project.json")
	}

	return nil
}

// Invite invites a user to the current project by email, potentially migrating a personal workspace to a shared one.
func (s *Service) Invite(email, role string) error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return fmt.Errorf("no project configured; run 'agentsecrets project use' first")
	}

	workspaceID := project.WorkspaceID
	if workspaceID == "" {
		return fmt.Errorf("no workspace found for this project")
	}

	// 1. Fetch Invitee's Public Key
	pubResp, err := s.API.Call("users.public_key", "GET", nil, map[string]string{"email": email})
	if err != nil {
		return fmt.Errorf("failed to fetch public key for %s: %w", email, err)
	}
	defer pubResp.Body.Close()

	if pubResp.StatusCode != http.StatusOK {
		return fmt.Errorf("user %s not found or has no public key", email)
	}

	var pubRes struct {
		Data struct {
			PublicKey string `json:"public_key"`
		} `json:"data"`
	}
	if err := json.NewDecoder(pubResp.Body).Decode(&pubRes); err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}

	inviteePubKey, err := base64.StdEncoding.DecodeString(pubRes.Data.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key format: %w", err)
	}

	// 2. Determine Workspace Type
	global, err := config.LoadGlobalConfig()
	if err != nil {
		return fmt.Errorf("failed to load global config: %w", err)
	}

	ws, ok := global.Workspaces[workspaceID]
	if !ok {
		return fmt.Errorf("workspace %s not found in local cache", workspaceID)
	}

	myEmail := config.GetEmail()
	myPubKey, err := keyring.GetPublicKey(myEmail)
	if err != nil {
		return fmt.Errorf("failed to load your public key from keyring: %w", err)
	}

	data := map[string]interface{}{
		"email": email,
		"role":  role,
	}

	var newWorkspaceKey []byte
	isMigrating := ws.Type == "personal" || ws.Type == ""

	if isMigrating {
		// Needs migration: Generate a new key and re-encrypt all secrets
		newWorkspaceKey, err = crypto.GenerateWorkspaceKey()
		if err != nil {
			return fmt.Errorf("failed to generate new workspace key: %w", err)
		}

		// Encrypt the new workspace key for both the owner and the invitee
		encForOwner, _ := crypto.EncryptForUser(myPubKey, newWorkspaceKey)
		encForInvitee, _ := crypto.EncryptForUser(inviteePubKey, newWorkspaceKey)

		data["encrypted_workspace_key_owner"] = base64.StdEncoding.EncodeToString(encForOwner)
		data["encrypted_workspace_key_invitee"] = base64.StdEncoding.EncodeToString(encForInvitee)

		// Fetch current secrets and re-encrypt them with the NEW key
		scrtResp, err := s.API.Call("secrets.list", "GET", nil, map[string]string{"project_id": project.ProjectID})
		if err != nil {
			return fmt.Errorf("failed to list current secrets for migration: %w", err)
		}
		defer scrtResp.Body.Close()

		var scrtRes struct {
			Data struct {
				Secrets []struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				} `json:"secrets"`
			} `json:"data"`
		}
		json.NewDecoder(scrtResp.Body).Decode(&scrtRes)

		oldWsKeyRaw, _ := base64.StdEncoding.DecodeString(ws.Key)
		var apiSecrets []map[string]string

		for _, secret := range scrtRes.Data.Secrets {
			plaintext, err := crypto.DecryptSecret(secret.Value, oldWsKeyRaw)
			if err != nil {
				continue // Skip failing secrets realistically
			}
			newEncrypted, _ := crypto.EncryptSecret(plaintext, newWorkspaceKey)
			apiSecrets = append(apiSecrets, map[string]string{"key": secret.Key, "value": newEncrypted})
		}
		data["secrets"] = apiSecrets

	} else {
		// Existing shared workspace: Just encrypt current workspace key for invitee
		wsKeyRaw, err := base64.StdEncoding.DecodeString(ws.Key)
		if err != nil {
			return fmt.Errorf("failed to decode current workspace key: %w", err)
		}

		encForInvitee, _ := crypto.EncryptForUser(inviteePubKey, wsKeyRaw)
		data["encrypted_workspace_key_invitee"] = base64.StdEncoding.EncodeToString(encForInvitee)
	}

	// 3. Send Invite to API
	invResp, err := s.API.Call("projects.invite", "POST", data, map[string]string{
		"workspace_id": workspaceID,
		"project_name": project.ProjectName,
	})
	if err != nil {
		return fmt.Errorf("failed to send invite: %w", err)
	}
	defer invResp.Body.Close()

	if invResp.StatusCode != http.StatusOK && invResp.StatusCode != http.StatusCreated {
		return s.API.DecodeError(invResp)
	}

	var result struct {
		Data struct {
			WorkspaceID          string `json:"workspace_id"`
			WorkspaceName        string `json:"workspace_name"`
			MigratedFromPersonal bool   `json:"migrated_from_personal"`
		} `json:"data"`
	}
	json.NewDecoder(invResp.Body).Decode(&result)

	// 4. Update local config if migrated
	if result.Data.MigratedFromPersonal && result.Data.WorkspaceID != "" {
		global.Workspaces[result.Data.WorkspaceID] = config.WorkspaceCacheEntry{
			Name: result.Data.WorkspaceName,
			Key:  base64.StdEncoding.EncodeToString(newWorkspaceKey),
			Role: "owner",
			Type: "shared",
		}
		config.SetSelectedWorkspaceID(result.Data.WorkspaceID)
		config.SaveGlobalConfig(global)

		project.WorkspaceID = result.Data.WorkspaceID
		project.WorkspaceName = result.Data.WorkspaceName
		config.SaveProjectConfig(project)
	}

	return nil
}
