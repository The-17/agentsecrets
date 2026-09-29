package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
)

func newRotationMock(t *testing.T) (*httptest.Server, *Service) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && r.URL.Path == "/secrets/prj-1/production/API_KEY/versions/":
			var body struct {
				Ciphertext string `json:"ciphertext"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Ciphertext == "" || body.Ciphertext == "plaintext-value" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"version_id": "ver-1", "staging_label": "pending",
				"rotation_reason": "routine", "created_at": "2026-09-29T00:00:00Z",
			}})
		case r.Method == "POST" && r.URL.Path == "/secrets/prj-1/production/API_KEY/promote/":
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"key": "API_KEY", "environment": "production",
				"current_version_id": "ver-1", "previous_version_id": "ver-0",
				"reason": "routine",
			}})
		case r.Method == "POST" && r.URL.Path == "/secrets/prj-1/production/API_KEY/rollback/":
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"key": "API_KEY", "environment": "production",
				"current_version_id": "ver-0", "previous_version_id": "ver-1",
			}})
		case r.Method == "DELETE" && r.URL.Path == "/secrets/prj-1/production/API_KEY/versions/pending/":
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{}})
		case r.Method == "GET" && r.URL.Path == "/secrets/prj-1/production/API_KEY/rotation/":
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"key": "API_KEY", "environment": "production",
				"policy": map[string]interface{}{"rotation_type": "value_client"},
				"versions": []map[string]interface{}{
					{"version_id": "ver-1", "staging_label": "current",
						"rotation_reason": "routine", "created_at": "2026-09-29T00:00:00Z"},
				},
			}})
		case r.Method == "PUT" && r.URL.Path == "/secrets/prj-1/production/API_KEY/rotation-policy/":
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"key": "API_KEY", "environment": "production",
				"policy": map[string]interface{}{"rotation_type": "value_client"},
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	client := api.NewClient(func() string { return "test-token" })
	client.BaseURL = server.URL
	return server, NewService(client)
}

func withRotationProject(t *testing.T) {
	t.Helper()
	tmpHome := t.TempDir()
	oldHome := config.HomeDirHook
	config.HomeDirHook = func() (string, error) { return tmpHome, nil }
	t.Cleanup(func() { config.HomeDirHook = oldHome })

	if err := config.InitGlobalConfig(); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	global, err := config.LoadGlobalConfig()
	if err != nil {
		t.Fatal(err)
	}
	if global.Workspaces == nil {
		global.Workspaces = map[string]config.WorkspaceCacheEntry{}
	}
	global.Workspaces["ws-1"] = config.WorkspaceCacheEntry{
		Name: "ws-1", Key: base64.StdEncoding.EncodeToString(raw), Role: "owner",
	}
	if err := config.SaveGlobalConfig(global); err != nil {
		t.Fatal(err)
	}

	origWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmpProj := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmpProj, ".agentsecrets"), 0700); err != nil {
		t.Fatal(err)
	}
	projectJSON, _ := json.Marshal(map[string]string{
		"project_id": "prj-1", "workspace_id": "ws-1", "environment": "production",
	})
	if err := os.WriteFile(filepath.Join(tmpProj, ".agentsecrets", "project.json"), projectJSON, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpProj); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWd) })
}

func TestStageVersionEncryptsClientSide(t *testing.T) {
	withRotationProject(t)
	_, svc := newRotationMock(t)

	staged, rotationID, err := svc.StageVersion("API_KEY", "plaintext-value", "production", "routine")
	if err != nil {
		t.Fatalf("StageVersion: %v", err)
	}
	if staged.VersionID != "ver-1" || staged.Staging != "pending" {
		t.Errorf("unexpected staged version: %+v", staged)
	}
	if rotationID == "" {
		t.Error("expected idempotency rotation id")
	}
}

func TestPromoteRollbackAbort(t *testing.T) {
	withRotationProject(t)
	_, svc := newRotationMock(t)

	promoted, err := svc.PromoteVersion("API_KEY", "production", "", "routine")
	if err != nil {
		t.Fatalf("PromoteVersion: %v", err)
	}
	if promoted.CurrentVersionID != "ver-1" || promoted.PreviousVersionID != "ver-0" {
		t.Errorf("unexpected promote result: %+v", promoted)
	}

	rolled, err := svc.RollbackVersion("API_KEY", "production")
	if err != nil {
		t.Fatalf("RollbackVersion: %v", err)
	}
	if rolled.CurrentVersionID != "ver-0" {
		t.Errorf("unexpected rollback result: %+v", rolled)
	}

	if err := svc.AbortPending("API_KEY", "production"); err != nil {
		t.Fatalf("AbortPending: %v", err)
	}
}

func TestRotationStatusAndPolicy(t *testing.T) {
	withRotationProject(t)
	_, svc := newRotationMock(t)

	status, err := svc.RotationStatus("API_KEY", "production")
	if err != nil {
		t.Fatalf("RotationStatus: %v", err)
	}
	if len(status.Versions) != 1 || status.Versions[0].Staging != "current" {
		t.Errorf("unexpected status: %+v", status)
	}

	period := 30
	if err := svc.SetRotationPolicy("API_KEY", "production", RotationPolicy{
		Type: "value_client", PeriodDays: &period, Enabled: true,
	}); err != nil {
		t.Fatalf("SetRotationPolicy: %v", err)
	}
}
