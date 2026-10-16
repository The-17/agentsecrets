package projects

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/crypto"
)

// TestTransfer_ReEncryptsSecretsForTargetWorkspace is the end-to-end contract
// test for `agentsecrets project transfer`. It proves the zero-knowledge
// invariant: the ciphertext the CLI posts to the server decrypts with the
// TARGET workspace key and no longer decrypts with the SOURCE workspace key —
// i.e. every secret was genuinely re-encrypted on the client, never sent in
// plaintext, and never left readable under the source key.
func TestTransfer_ReEncryptsSecretsForTargetWorkspace(t *testing.T) {
	srcKey, err := crypto.GenerateWorkspaceKey()
	if err != nil {
		t.Fatalf("generate source key: %v", err)
	}
	tgtKey, err := crypto.GenerateWorkspaceKey()
	if err != nil {
		t.Fatalf("generate target key: %v", err)
	}

	const plaintext = "the-one-secret-value"
	cipherSrc, err := crypto.EncryptSecret(plaintext, srcKey)
	if err != nil {
		t.Fatalf("encrypt source secret: %v", err)
	}

	type transferBody struct {
		TargetWorkspaceID string `json:"target_workspace_id"`
		Secrets           []struct {
			ID    string `json:"id"`
			Value string `json:"value"`
		} `json:"secrets"`
	}

	var (
		gotTransferPath string
		gotBody         transferBody
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/projects/":
			_, _ = w.Write([]byte(`{"status":"success","data":[{"id":"p1","name":"scratch","workspace_id":"wsA","description":""}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/secrets/p1/":
			if r.URL.Query().Get("environment") == "development" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status": "success",
					"data": map[string]any{
						"project_id": "p1",
						"secrets": []map[string]any{
							{"id": "s1", "key": "MY_KEY", "value": cipherSrc},
						},
					},
				})
				return
			}
			_, _ = w.Write([]byte(`{"status":"success","data":{"project_id":"p1","secrets":[]}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/projects/wsA/scratch/transfer/":
			gotTransferPath = r.URL.Path
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			_, _ = w.Write([]byte(`{"status":"success","data":{"project_id":"p1","project_name":"scratch","source_workspace_id":"wsA","source_workspace_name":"A","target_workspace_id":"wsB","target_workspace_name":"B","secrets_transferred":1}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	orig := workspaceKeyResolver
	workspaceKeyResolver = func(id string) ([]byte, error) {
		switch id {
		case "wsA":
			return srcKey, nil
		case "wsB":
			return tgtKey, nil
		}
		return nil, fmt.Errorf("unexpected workspace %q", id)
	}
	defer func() { workspaceKeyResolver = orig }()

	svc := NewService(api.NewClientWithURL(srv.URL, func() string { return "test-token" }))

	res, err := svc.Transfer("scratch", "wsB")
	if err != nil {
		t.Fatalf("Transfer returned error: %v", err)
	}
	if res.SecretsTransferred != 1 {
		t.Fatalf("secrets_transferred = %d, want 1", res.SecretsTransferred)
	}

	if gotTransferPath != "/projects/wsA/scratch/transfer/" {
		t.Fatalf("transfer path = %q, want %q", gotTransferPath, "/projects/wsA/scratch/transfer/")
	}
	if gotBody.TargetWorkspaceID != "wsB" {
		t.Fatalf("target_workspace_id = %q, want wsB", gotBody.TargetWorkspaceID)
	}
	if len(gotBody.Secrets) != 1 || gotBody.Secrets[0].ID != "s1" {
		t.Fatalf("posted secrets = %+v, want exactly one entry with id s1", gotBody.Secrets)
	}

	got, err := crypto.DecryptSecret(gotBody.Secrets[0].Value, tgtKey)
	if err != nil {
		t.Fatalf("re-encrypted value must decrypt with the TARGET key: %v", err)
	}
	if got != plaintext {
		t.Fatalf("plaintext after re-encryption = %q, want %q", got, plaintext)
	}

	if _, err := crypto.DecryptSecret(gotBody.Secrets[0].Value, srcKey); err == nil {
		t.Fatalf("value still decrypts with the SOURCE key — secrets were NOT re-encrypted")
	}
}
