// Package migration moves an account's data between AgentSecrets servers.
//
// The control plane owns the data movement. On export it strips its own Fernet
// layer and hands back the untouched client-side AES ciphertexts; on import it
// re-wraps them under the destination server's key. The CLI never sees a
// plaintext secret — it only relays opaque JSON — so this package is a thin,
// typed client over three routes:
//
//	POST /api/migration/token/   mint a short-lived, single-use migration token
//	POST /api/migration/export/  fetch a portable bundle (token-authenticated)
//	POST /api/migration/import/  write a bundle into the current server
//
// Both directions work: a self-hosted user can pull their data down off
// AgentSecrets Cloud onto their own server, or push it back up.
package migration

import (
	"encoding/json"

	"github.com/The-17/agentsecrets/pkg/api"
)

// Token is the payload of POST /api/migration/token/. It is a signed,
// 30-minute, single-use credential scoped to exporting the caller's data.
type Token struct {
	Token          string `json:"token"`
	ExpiresAt      string `json:"expires_at"`
	UserEmail      string `json:"user_email"`
	WorkspaceCount int    `json:"workspace_count"`
}

// ImportSummary reports what a bundle created on the target server.
type ImportSummary struct {
	WorkspacesImported       int `json:"workspaces_imported"`
	ProjectsImported         int `json:"projects_imported"`
	SecretsImported          int `json:"secrets_imported"`
	AgentsImported           int `json:"agents_imported"`
	AllowlistEntriesImported int `json:"allowlist_entries_imported"`
}

// ImportResult is the payload of POST /api/migration/import/.
type ImportResult struct {
	Status    string        `json:"status"`
	UserEmail string        `json:"user_email"`
	Summary   ImportSummary `json:"summary"`
}

// Bundle is a portable export payload. It is carried as opaque JSON: the shape
// belongs to the server (see apps/migration/schemas.py), and the CLI must not
// depend on it to stay forward-compatible with new bundle fields.
type Bundle = json.RawMessage

// Service talks to the migration routes on one server.
type Service struct {
	API *api.Client
}

// NewService creates a migration service backed by the given API client.
func NewService(client *api.Client) *Service {
	return &Service{API: client}
}

// CreateToken mints a single-use migration token on the current (source)
// server. It requires an authenticated session.
func (s *Service) CreateToken() (*Token, error) {
	tok, err := api.CallJSON[Token](s.API, "migration.token", "POST", nil, nil, nil)
	if err != nil {
		return nil, err
	}
	return &tok, nil
}

// Export fetches the portable bundle from the current server.
//
// The migration token is sent in the request body, which is where the route
// looks first. The caller's session JWT is deliberately NOT attached: export
// is authorized by the migration token alone, and a token-only request can
// never trigger a session refresh or leak the session onto the migration path.
func (s *Service) Export(token string) (Bundle, error) {
	client := api.NewClientWithURL(s.API.BaseURL, nil)
	return api.CallJSON[Bundle](client, "migration.export", "POST", map[string]string{"token": token}, nil, nil)
}

// ImportFromSource asks the current (destination) server to pull a bundle from
// sourceURL itself. sourceURL is the bare base URL of the source server, with
// no /api suffix — the destination appends the export path.
func (s *Service) ImportFromSource(sourceURL, token string) (*ImportResult, error) {
	body := map[string]string{
		"source_url": sourceURL,
		"token":      token,
	}
	res, err := api.CallJSON[ImportResult](s.API, "migration.import", "POST", body, nil, nil)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// ImportBundle writes a bundle previously produced by Export into the current
// server.
func (s *Service) ImportBundle(bundle Bundle) (*ImportResult, error) {
	body := map[string]interface{}{"bundle": bundle}
	res, err := api.CallJSON[ImportResult](s.API, "migration.import", "POST", body, nil, nil)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
