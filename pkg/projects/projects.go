// Package projects handles project creation, selection, updates, deletion, and team invites within workspaces.
package projects

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"strings"
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
	return api.CallJSON[[]Project](s.API, "projects.list", "GET", nil, nil, nil)
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

	resp, err := api.CallJSON[Project](s.API, "projects.create", "POST", data, nil, nil, http.StatusCreated)
	if err != nil {
		return nil, fmt.Errorf("create project: %w", err)
	}

	// Bind locally
	if err := s.bindLocally(&resp); err != nil {
		return nil, fmt.Errorf("create project: bind: %w", err)
	}

	return &resp, nil
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

	resp, err := api.CallJSON[Project](s.API, "projects.get", "GET", nil, params, nil)
	if err != nil {
		return nil, fmt.Errorf("use project: %w", err)
	}

	// Update local config
	if err := s.bindLocally(&resp); err != nil {
		return nil, fmt.Errorf("use project: bind: %w", err)
	}

	return &resp, nil
}

// bindLocally updates the fields in the existing .agentsecrets/project.json
func (s *Service) bindLocally(project *Project) error {
	root, _ := config.GetProjectRoot()
	if root == "" {
		root = "."
	}
	projectDir := filepath.Join(root, ".agentsecrets")
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

	// Save globally so exec provider can find it regardless of working directory
	_ = config.SetSelectedProjectID(project.ID)

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

	if err := s.API.CallNoContent("projects.update", "PATCH", data, params, nil); err != nil {
		return fmt.Errorf("update project: %w", err)
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
		if err := config.SaveProjectConfig(local); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: rename succeeded on cloud but failed to update local project config: %v\n", err)
		}
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

	if err := s.API.CallNoContent("projects.delete", "DELETE", nil, params, nil); err != nil {
		return fmt.Errorf("delete project: %w", err)
	}

	// Unbind local project info if we just deleted the active one
	local, err := config.LoadProjectConfig()
	if err == nil && local != nil && local.ProjectName == name && local.WorkspaceID == workspaceID {
		root, _ := config.GetProjectRoot()
		if root != "" {
			os.Remove(filepath.Join(root, ".agentsecrets", "project.json"))
		}
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
	pubResp, err := s.API.Call("users.public_key", "GET", nil, map[string]string{"email": email}, nil)
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
	isMigrating := strings.EqualFold(ws.Type, "personal") || ws.Type == ""

	if isMigrating {
		// Needs migration: Generate a new key and re-encrypt all secrets
		newWorkspaceKey, err = crypto.GenerateWorkspaceKey()
		if err != nil {
			return fmt.Errorf("failed to generate new workspace key: %w", err)
		}

		// Encrypt the new workspace key for both the owner and the invitee
		encForOwner, err := crypto.EncryptForUser(myPubKey, newWorkspaceKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt workspace key for owner: %w", err)
		}
		encForInvitee, err := crypto.EncryptForUser(inviteePubKey, newWorkspaceKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt workspace key for invitee: %w", err)
		}

		data["encrypted_workspace_key_owner"] = base64.StdEncoding.EncodeToString(encForOwner)
		data["encrypted_workspace_key_invitee"] = base64.StdEncoding.EncodeToString(encForInvitee)

		oldWsKeyRaw, err := config.GetWorkspaceKey(workspaceID)
		if err != nil {
			return fmt.Errorf("failed to load old workspace key: %w", err)
		}

		apiSecrets := []map[string]string{}
		environments := config.ValidEnvironments

		for _, env := range environments {
			scrtResp, err := s.API.Call("secrets.list", "GET", nil, map[string]string{"project_id": project.ProjectID}, map[string]string{"environment": env})
			if err != nil {
				continue // Skip environments that fail or don't exist
			}

			var scrtRes struct {
				Data struct {
					Secrets []struct {
						Key   string `json:"key"`
						Value string `json:"value"`
					} `json:"secrets"`
				} `json:"data"`
			}

			if err := json.NewDecoder(scrtResp.Body).Decode(&scrtRes); err != nil {
				scrtResp.Body.Close()
				continue
			}
			scrtResp.Body.Close()

			for _, secret := range scrtRes.Data.Secrets {
				plaintext, err := crypto.DecryptSecret(secret.Value, oldWsKeyRaw)
				if err != nil {
					return fmt.Errorf("failed to decrypt secret %q in %s: %w", secret.Key, env, err)
				}
				newEncrypted, err := crypto.EncryptSecret(plaintext, newWorkspaceKey)
				if err != nil {
					return fmt.Errorf("failed to re-encrypt secret %q in %s: %w", secret.Key, env, err)
				}

				apiSecrets = append(apiSecrets, map[string]string{
					"key":         secret.Key,
					"value":       newEncrypted,
					"environment": env,
				})
			}
		}

		data["secrets"] = apiSecrets

	} else {
		// Existing shared workspace: Just encrypt current workspace key for invitee
		wsKeyRaw, err := base64.StdEncoding.DecodeString(ws.Key)
		if err != nil {
			return fmt.Errorf("failed to decode current workspace key: %w", err)
		}

		encForInvitee, err := crypto.EncryptForUser(inviteePubKey, wsKeyRaw)
		if err != nil {
			return fmt.Errorf("failed to encrypt workspace key for invitee: %w", err)
		}
		data["encrypted_workspace_key_invitee"] = base64.StdEncoding.EncodeToString(encForInvitee)
	}

	// 3. Send Invite to API
	invResp, err := s.API.Call("projects.invite", "POST", data, map[string]string{
		"workspace_id": workspaceID,
		"project_name": project.ProjectName,
	}, nil)
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
	if err := json.NewDecoder(invResp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode invite response: %w", err)
	}

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

// ProjectTransferResult holds the result of a project transfer between workspaces.
type ProjectTransferResult struct {
	ProjectID           string `json:"project_id"`
	ProjectName         string `json:"project_name"`
	SourceWorkspaceID   string `json:"source_workspace_id"`
	SourceWorkspaceName string `json:"source_workspace_name"`
	TargetWorkspaceID   string `json:"target_workspace_id"`
	TargetWorkspaceName string `json:"target_workspace_name"`
	SecretsTransferred int    `json:"secrets_transferred"`
}

// Transfer re-encrypts all secrets in a project from source to target workspace key and executes the transfer on the server.
func (s *Service) Transfer(projectName, targetWorkspaceID string) (*ProjectTransferResult, error) {
	sourceWsID := config.GetSelectedWorkspaceID()
	if sourceWsID == "" {
		return nil, fmt.Errorf("no workspace currently selected; run 'agentsecrets workspace switch' first")
	}
	if sourceWsID == targetWorkspaceID {
		return nil, fmt.Errorf("project is already in this workspace")
	}

	// 1. Load source and destination workspace keys
	sourceKey, err := config.GetWorkspaceKey(sourceWsID)
	if err != nil {
		return nil, fmt.Errorf("failed to load source workspace key: %w", err)
	}

	targetKey, err := config.GetWorkspaceKey(targetWorkspaceID)
	if err != nil {
		return nil, fmt.Errorf("failed to load target workspace key: %w", err)
	}

	// 2. Resolve target project
	projs, err := s.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}
	var targetProject *Project
	for _, p := range projs {
		if strings.EqualFold(p.Name, projectName) || p.ID == projectName {
			targetProject = &p
			break
		}
	}
	if targetProject == nil {
		return nil, fmt.Errorf("project %q not found in current workspace", projectName)
	}

	// 3. Fetch secrets across all environments and re-encrypt under target key
	reencryptedSecrets := []map[string]string{}
	for _, env := range config.ValidEnvironments {
		scrtResp, err := s.API.Call("secrets.list", "GET", nil, map[string]string{"project_id": targetProject.ID}, map[string]string{"environment": env})
		if err != nil {
			continue
		}
		var scrtRes struct {
			Data struct {
				Secrets []struct {
					ID    string `json:"id"`
					Key   string `json:"key"`
					Value string `json:"value"`
				} `json:"secrets"`
			} `json:"data"`
		}
		if err := json.NewDecoder(scrtResp.Body).Decode(&scrtRes); err != nil {
			scrtResp.Body.Close()
			continue
		}
		scrtResp.Body.Close()

		for _, scrt := range scrtRes.Data.Secrets {
			if scrt.Value == "" {
				continue
			}
			plaintext, err := crypto.DecryptSecret(scrt.Value, sourceKey)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt secret %s: %w", scrt.Key, err)
			}
			newEnc, err := crypto.EncryptSecret(plaintext, targetKey)
			if err != nil {
				return nil, fmt.Errorf("failed to re-encrypt secret %s: %w", scrt.Key, err)
			}
			reencryptedSecrets = append(reencryptedSecrets, map[string]string{
				"id":    scrt.ID,
				"value": newEnc,
			})
		}
	}

	// 4. Send transfer request to server
	payload := map[string]interface{}{
		"target_workspace_id": targetWorkspaceID,
		"secrets":             reencryptedSecrets,
	}

	resp, err := s.API.Call("projects.transfer", "POST", payload, map[string]string{
		"project_name": targetProject.Name,
	}, map[string]string{
		"source_workspace_id": sourceWsID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to transfer project: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, s.API.DecodeError(resp)
	}

	var res struct {
		Data ProjectTransferResult `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to decode transfer response: %w", err)
	}

	// 5. Update local project binding if current folder is linked
	localProj, _ := config.LoadProjectConfig()
	if localProj != nil && (localProj.ProjectID == targetProject.ID || strings.EqualFold(localProj.ProjectName, targetProject.Name)) {
		localProj.WorkspaceID = targetWorkspaceID
		localProj.WorkspaceName = res.Data.TargetWorkspaceName
		_ = config.SaveProjectConfig(localProj)
	}

	return &res.Data, nil
}
