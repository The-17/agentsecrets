package workspaces

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
)

// InviteBatch must never seal an empty workspace key.
//
// StoreWorkspaceCache strips the key out of config.json and keeps it in the OS
// keyring, so cfg.Workspaces[id].Key is always "". Decoding that yielded an
// empty key with no error, the CLI sealed it, and the server marked the
// membership active because the envelope was non-empty: the invitee could see
// the workspace and never decrypt anything in it.
func TestInviteBatchRefusesToSealAnEmptyWorkspaceKey(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return tmpDir, nil }
	defer func() { config.HomeDirHook = oldHome }()

	if err := config.InitGlobalConfig(); err != nil {
		t.Fatalf("InitGlobalConfig: %v", err)
	}

	cfg, err := config.LoadGlobalConfig()
	if err != nil {
		t.Fatalf("LoadGlobalConfig: %v", err)
	}
	// Exactly the shape StoreWorkspaceCache leaves behind: metadata, no key.
	cfg.Workspaces = map[string]config.WorkspaceCacheEntry{
		"ws-team": {Name: "The Seventeen", Role: "member", Type: "shared"},
	}
	if err := config.SaveGlobalConfig(cfg); err != nil {
		t.Fatalf("SaveGlobalConfig: %v", err)
	}

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := NewService(api.NewClientWithURL(server.URL, func() string { return "test-token" }))

	_, err = svc.InviteBatch("ws-team", []string{"new@example.com"}, "member")
	if err == nil {
		t.Fatal("invite succeeded with no workspace key: the invitee would receive an envelope that seals nothing")
	}
	if !strings.Contains(err.Error(), "The Seventeen") {
		t.Fatalf("error should name the workspace, got: %v", err)
	}
	if requests != 0 {
		t.Fatalf("an invite request was sent despite the missing key (%d requests)", requests)
	}
}
