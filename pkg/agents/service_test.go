package agents

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
)

func newRotationMock(t *testing.T) (*httptest.Server, *Service) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && r.URL.Path == "/workspaces/ws-1/agents/areg-1/tokens/tok-1/rotate/":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"token": "agt_ws_1_NEW", "token_id": "tok-2", "label": "w1",
				"rotation": map[string]interface{}{
					"rotation_state": "active", "rotation_family_id": "tok-1",
					"rotation_due": false,
				},
			}})
		case r.Method == "PUT" && r.URL.Path == "/workspaces/ws-1/agents/areg-1/tokens/tok-1/rotation-policy/":
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"id": "tok-1",
				"rotation": map[string]interface{}{
					"rotation_state": "active", "rotation_period_days": 30,
					"next_rotation_at": "2026-10-28T00:00:00Z", "rotation_due": false,
				},
			}})
		case r.Method == "GET" && r.URL.Path == "/workspaces/ws-1/agents/areg-1/tokens/":
			json.NewEncoder(w).Encode(map[string]interface{}{"data": []Token{
				{ID: "tok-1", Label: "w1", Status: "superseded_overlap", RotationState: "superseded"},
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

func TestTokenRotate(t *testing.T) {
	_, svc := newRotationMock(t)
	overlap := 24
	resp, err := svc.TokenRotate("ws-1", "areg-1", "tok-1", RotateTokenRequest{
		OverlapHours: &overlap, Reason: "routine",
	})
	if err != nil {
		t.Fatalf("TokenRotate: %v", err)
	}
	if resp.Token != "agt_ws_1_NEW" || resp.TokenID != "tok-2" {
		t.Errorf("unexpected rotate response: %+v", resp)
	}
	if resp.Rotation.FamilyID != "tok-1" || resp.Rotation.State != "active" {
		t.Errorf("unexpected rotation block: %+v", resp.Rotation)
	}
}

func TestTokenRotationSet(t *testing.T) {
	_, svc := newRotationMock(t)
	period := 30
	resp, err := svc.TokenRotationSet("ws-1", "areg-1", "tok-1", RotationPolicyRequest{
		PeriodDays: &period, Enabled: true,
	})
	if err != nil {
		t.Fatalf("TokenRotationSet: %v", err)
	}
	if resp.Rotation.PeriodDays == nil || *resp.Rotation.PeriodDays != 30 {
		t.Errorf("unexpected policy response: %+v", resp)
	}
}

func TestTokenListParsesRotation(t *testing.T) {
	_, svc := newRotationMock(t)
	tokens, err := svc.TokenList("ws-1", "areg-1")
	if err != nil {
		t.Fatalf("TokenList: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("tokens = %d, want 1", len(tokens))
	}
	if tokens[0].Status != "superseded_overlap" || tokens[0].RotationState != "superseded" {
		t.Errorf("rotation fields not parsed: %+v", tokens[0])
	}
}
