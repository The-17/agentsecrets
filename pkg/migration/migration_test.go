package migration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
)

// newTestClient starts an httptest server wired with the given routes and
// returns an API client pointed at its /api root with a fixed session JWT.
func newTestClient(t *testing.T, routes map[string]http.HandlerFunc) *api.Client {
	t.Helper()
	mux := http.NewServeMux()
	for path, h := range routes {
		mux.HandleFunc(path, h)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return api.NewClientWithURL(srv.URL+"/api", func() string { return "session-jwt" })
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestCreateToken(t *testing.T) {
	var gotMethod, gotAuth string
	client := newTestClient(t, map[string]http.HandlerFunc{
		"/api/migration/token/": func(w http.ResponseWriter, r *http.Request) {
			gotMethod, gotAuth = r.Method, r.Header.Get("Authorization")
			writeJSON(w, map[string]interface{}{
				"status": "success",
				"data": map[string]interface{}{
					"token":           "mig-token-123",
					"expires_at":      "2026-10-19T23:00:00+00:00",
					"user_email":      "user@example.com",
					"workspace_count": 2,
				},
			})
		},
	})

	tok, err := NewService(client).CreateToken()
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotAuth != "Bearer session-jwt" {
		t.Errorf("token route must carry the session JWT, got %q", gotAuth)
	}
	if tok.Token != "mig-token-123" || tok.UserEmail != "user@example.com" || tok.WorkspaceCount != 2 {
		t.Errorf("decoded token = %+v", tok)
	}
}

func TestCreateTokenSurfacesAPIError(t *testing.T) {
	client := newTestClient(t, map[string]http.HandlerFunc{
		"/api/migration/token/": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, map[string]string{"message": "Authentication credentials were not provided."})
		},
	})

	if _, err := NewService(client).CreateToken(); err == nil {
		t.Fatal("expected an error for a 401 response, got nil")
	}
}

func TestExportSendsTokenInBodyAndNoJWT(t *testing.T) {
	var gotAuth, gotToken string
	client := newTestClient(t, map[string]http.HandlerFunc{
		"/api/migration/export/": func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotToken = body["token"]
			writeJSON(w, map[string]interface{}{
				"status": "success",
				"data": map[string]interface{}{
					"version":     "1.0",
					"exported_at": "2026-10-19T22:00:00+00:00",
					"user":        map[string]string{"email": "user@example.com"},
					"workspaces":  []interface{}{},
				},
			})
		},
	})

	bundle, err := NewService(client).Export("mig-token-123")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if gotToken != "mig-token-123" {
		t.Errorf("export body token = %q, want the migration token", gotToken)
	}
	if gotAuth != "" {
		t.Errorf("export must not attach the session JWT, got %q", gotAuth)
	}

	var decoded struct {
		Version string `json:"version"`
		User    struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.Unmarshal(bundle, &decoded); err != nil {
		t.Fatalf("bundle is not valid JSON: %v", err)
	}
	if decoded.Version != "1.0" || decoded.User.Email != "user@example.com" {
		t.Errorf("decoded bundle = %+v", decoded)
	}
}

func TestImportFromSourceSendsSourceAndToken(t *testing.T) {
	var gotAuth string
	var gotBody map[string]string
	client := newTestClient(t, map[string]http.HandlerFunc{
		"/api/migration/import/": func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			writeJSON(w, map[string]interface{}{
				"status": "success",
				"data": map[string]interface{}{
					"status":     "success",
					"user_email": "user@example.com",
					"summary": map[string]int{
						"workspaces_imported": 1, "projects_imported": 2,
						"secrets_imported": 3, "agents_imported": 4,
						"allowlist_entries_imported": 5,
					},
				},
			})
		},
	})

	res, err := NewService(client).ImportFromSource("https://source.example.com", "mig-token-123")
	if err != nil {
		t.Fatalf("ImportFromSource: %v", err)
	}
	if gotAuth != "Bearer session-jwt" {
		t.Errorf("import requires the destination session JWT, got %q", gotAuth)
	}
	if gotBody["source_url"] != "https://source.example.com" || gotBody["token"] != "mig-token-123" {
		t.Errorf("import body = %v", gotBody)
	}
	if res.Summary.SecretsImported != 3 || res.Summary.AllowlistEntriesImported != 5 {
		t.Errorf("decoded summary = %+v", res.Summary)
	}
}

func TestImportBundleSendsBundlePayload(t *testing.T) {
	var raw map[string]json.RawMessage
	client := newTestClient(t, map[string]http.HandlerFunc{
		"/api/migration/import/": func(w http.ResponseWriter, r *http.Request) {
			var body map[string]json.RawMessage
			_ = json.NewDecoder(r.Body).Decode(&body)
			raw = body
			writeJSON(w, map[string]interface{}{
				"status": "success",
				"data": map[string]interface{}{
					"status": "success", "user_email": "user@example.com",
					"summary": map[string]int{"workspaces_imported": 1},
				},
			})
		},
	})

	bundle := json.RawMessage(`{"version":"1.0","workspaces":[]}`)
	if _, err := NewService(client).ImportBundle(bundle); err != nil {
		t.Fatalf("ImportBundle: %v", err)
	}
	if _, ok := raw["bundle"]; !ok {
		t.Fatalf("import request must nest the bundle under 'bundle', got keys %v", raw)
	}
	var sent struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw["bundle"], &sent); err != nil || sent.Version != "1.0" {
		t.Errorf("bundle relayed incorrectly: %s (err=%v)", string(raw["bundle"]), err)
	}
}
