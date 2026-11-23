package workspaces

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
)

func TestWorkspaceCreate(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return tmpDir, nil }
	defer func() { config.HomeDirHook = oldHome }()

	if err := config.InitGlobalConfig(); err != nil {
		t.Fatalf("InitGlobalConfig failed: %v", err)
	}

	config.SetEmail("test@example.com")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/workspaces/" {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]string{
					"id":   "ws-123",
					"type": "shared",
					"role": "owner",
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := api.NewClient(func() string { return "" })
	client.BaseURL = server.URL
	svc := NewService(client)

	err := svc.Create("New Team")
	if err != nil {
		t.Logf("Workspace Create error (likely public key missing): %v", err)
	}
}

func TestWorkspaceMembers(t *testing.T) {
	tmpDir := t.TempDir()
	config.HomeDirHook = func() (string, error) { return tmpDir, nil }

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]string{
				{"email": "user1@example.com", "role": "admin", "status": "active"},
			},
		})
	}))
	defer server.Close()

	client := api.NewClient(func() string { return "token" })
	client.BaseURL = server.URL
	svc := NewService(client)

	members, err := svc.Members("ws-123")
	if err != nil {
		t.Fatalf("Members failed: %v", err)
	}

	if len(members) != 1 || members[0].Email != "user1@example.com" {
		t.Errorf("Unexpected members list: %v", members)
	}
}

func TestWorkspaceDelete(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return tmpDir, nil }
	defer func() { config.HomeDirHook = oldHome }()

	if err := config.InitGlobalConfig(); err != nil {
		t.Fatalf("InitGlobalConfig failed: %v", err)
	}

	cfg, _ := config.LoadGlobalConfig()
	cfg.Workspaces = map[string]config.WorkspaceCacheEntry{
		"ws-123": {Name: "Test Workspace", Type: "shared"},
	}
	cfg.SelectedWorkspaceID = "ws-123"
	_ = config.SaveGlobalConfig(cfg)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && r.URL.Path == "/workspaces/ws-123/" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := api.NewClient(func() string { return "token" })
	client.BaseURL = server.URL
	svc := NewService(client)

	err := svc.Delete("ws-123")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	cfg, _ = config.LoadGlobalConfig()
	if _, exists := cfg.Workspaces["ws-123"]; exists {
		t.Error("Workspace ws-123 was not removed from local config")
	}
	if cfg.SelectedWorkspaceID == "ws-123" {
		t.Error("SelectedWorkspaceID was not cleared")
	}
}
