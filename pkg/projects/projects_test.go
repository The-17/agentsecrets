package projects

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
)

func TestProjectService(t *testing.T) {
	// Setup: redirect home directory to a temp one for global config
	tmpHome := t.TempDir()
	oldHome := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return tmpHome, nil }
	defer func() { config.HomeDirHook = oldHome }()

	// 1. Mock API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		switch {
		case r.Method == "GET" && r.URL.Path == "/projects/":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []Project{
					{ID: "p-1", Name: "app-1", WorkspaceID: "ws-1"},
				},
			})
		case r.Method == "POST" && r.URL.Path == "/projects/":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": Project{ID: "p-new", Name: "app-new", WorkspaceID: "ws-1"},
			})
		case r.Method == "GET" && r.URL.Path == "/projects/ws-1/app-target/":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": Project{ID: "p-target", Name: "app-target", WorkspaceID: "ws-1"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// 2. Client & Service Setup
	client := api.NewClient(func() string { return "test-token" })
	client.BaseURL = server.URL
	svc := NewService(client)

	// Setup virtual local project dir
	origWd, _ := os.Getwd()
	tmpProjDir := t.TempDir()
	os.Chdir(tmpProjDir)
	defer os.Chdir(origWd)

	// Initialize global config with a workspace
	config.InitGlobalConfig()
	config.SetSelectedWorkspaceID("ws-1")

	// 3. Test List
	projects, err := svc.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(projects) != 1 || projects[0].Name != "app-1" {
		t.Errorf("Unexpected list result: %v", projects)
	}

	// 4. Test Create
	newProj, err := svc.Create("app-new", "new desc")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if newProj.ID != "p-new" {
		t.Errorf("Unexpected created project: %v", newProj)
	}

	// Verify local config was updated
	projConf, err := config.LoadProjectConfig()
	if err != nil || projConf.ProjectID != "p-new" {
		t.Errorf("Local project.json not updated correctly: %v", projConf)
	}

	// 5. Test Use
	targetProj, err := svc.Use("app-target")
	if err != nil {
		t.Fatalf("Use failed: %v", err)
	}
	if targetProj.ID != "p-target" {
		t.Errorf("Unexpected project in Use: %v", targetProj)
	}

	// Verify local config was updated again
	projConf, _ = config.LoadProjectConfig()
	if projConf.ProjectID != "p-target" {
		t.Errorf("Local project.json not updated in Use: %v", projConf)
	}

	// 6. Test Failure Cases (Negative testing)
	_, err = svc.Use("non-existent")
	if err == nil {
		t.Error("Use should have failed for non-existent project")
	}
}
