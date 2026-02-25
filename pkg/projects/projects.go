package projects

import (
	"encoding/json"
	"fmt"
	"os"
	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
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

	if resp.StatusCode != 200 {
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

	if resp.StatusCode != 201 {
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

	if resp.StatusCode != 200 {
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
