package workspaces

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/keyring"
)

// Workspace is one membership exactly as the server reports it.
type Workspace struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	Type                  string `json:"type"`
	Role                  string `json:"role"`
	EncryptedWorkspaceKey string `json:"encrypted_workspace_key"`
}

// RefreshResult reports what changed in the local workspace cache.
type RefreshResult struct {
	Added   []string
	Removed []string
	Changed []string
	// Locked names workspaces that are visible but whose workspace key could
	// not be unwrapped. They are listed, and nothing in them will resolve
	// until an admin re-invites the user, so saying nothing here turns into a
	// confusing "workspace key not found" three commands later.
	Locked []string
}

// HasChanges reports whether anything about the caller's memberships moved.
func (r RefreshResult) HasChanges() bool {
	return len(r.Added) > 0 || len(r.Removed) > 0 || len(r.Changed) > 0
}

// List returns every workspace the caller is an active member of.
func (s *Service) List() ([]Workspace, error) {
	resp, err := s.API.Call("workspaces.list", "GET", nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("list workspaces: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, s.API.DecodeError(resp)
	}

	var res struct {
		Data []Workspace `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("list workspaces: failed to parse response: %w", err)
	}
	return res.Data, nil
}

// Refresh re-reads the caller's memberships from the server and updates the
// local cache, decrypting the workspace key for any workspace the user has
// just gained access to.
//
// The cache used to be written once, at login, which meant an invitation was
// invisible until the user logged out and back in. The user's private key is
// already in the OS keyring, so a refresh can unwrap a newly shared workspace
// key without the password and without re-authenticating.
func (s *Service) Refresh() (RefreshResult, error) {
	email := config.GetEmail()
	if email == "" {
		return RefreshResult{}, fmt.Errorf("not logged in")
	}

	listed, err := s.List()
	if err != nil {
		return RefreshResult{}, err
	}

	priv, err := keyring.GetPrivateKey(email)
	if err != nil {
		return RefreshResult{}, fmt.Errorf("refresh workspaces: private key unavailable: %w", err)
	}
	pub, err := keyring.GetPublicKey(email)
	if err != nil {
		return RefreshResult{}, fmt.Errorf("refresh workspaces: public key unavailable: %w", err)
	}

	// Decrypt every workspace key the server handed back. A workspace whose key
	// cannot be unwrapped is reported, not hidden: it stays in the cache so its
	// name is visible, but the user is told it is unusable instead of meeting a
	// "workspace key not found" error on the next command.
	decrypted, locked := unlockWorkspaceKeys(listed, priv, pub)

	cfg, _ := config.LoadGlobalConfig()
	if cfg == nil {
		cfg = &config.GlobalConfig{}
	}

	keyFor := func(id string) string {
		if key, ok := decrypted[id]; ok && key != "" {
			return key
		}
		if key, err := config.GetWorkspaceKey(id); err == nil {
			return crypto.B64Encode(key)
		}
		return ""
	}

	merged, result := mergeWorkspaceCache(cfg.Workspaces, listed, keyFor)
	result.Locked = locked

	if err := config.StoreWorkspaceCache(merged); err != nil {
		return result, fmt.Errorf("refresh workspaces: failed to save cache: %w", err)
	}
	if err := config.MarkWorkspacesSynced(); err != nil {
		return result, fmt.Errorf("refresh workspaces: failed to record sync time: %w", err)
	}

	return result, nil
}

// unlockWorkspaceKeys unwraps each membership's workspace key and names the
// workspaces it could not unlock.
//
// Silence here is expensive: a workspace whose key is missing still appears in
// the list and can be selected, and the failure only surfaces later as
// "workspace key not found" from an unrelated command. Callers report Locked
// immediately so the user knows to ask for a re-invite.
func unlockWorkspaceKeys(listed []Workspace, priv, pub []byte) (map[string]string, []string) {
	decrypted := make(map[string]string, len(listed))
	var locked []string

	for _, ws := range listed {
		raw, err := base64.StdEncoding.DecodeString(ws.EncryptedWorkspaceKey)
		if err != nil || len(raw) == 0 {
			locked = append(locked, ws.Name)
			continue
		}
		key, err := crypto.DecryptFromUser(priv, pub, raw)
		if err != nil || len(key) == 0 {
			// A valid envelope that opens to nothing is as unusable as one that
			// does not open at all: there is no key to store, and reporting
			// success here is what left a workspace selectable but broken.
			locked = append(locked, ws.Name)
			continue
		}
		decrypted[ws.ID] = crypto.B64Encode(key)
	}

	return decrypted, locked
}

// mergeWorkspaceCache folds the server's membership list into the local cache
// and reports what moved. It is pure so the diffing can be tested without a
// server or a keyring.
func mergeWorkspaceCache(
	current map[string]config.WorkspaceCacheEntry,
	listed []Workspace,
	keyFor func(string) string,
) (map[string]config.WorkspaceCacheEntry, RefreshResult) {
	var result RefreshResult
	merged := make(map[string]config.WorkspaceCacheEntry, len(listed))

	for _, ws := range listed {
		entry := config.WorkspaceCacheEntry{
			Name: ws.Name,
			Key:  keyFor(ws.ID),
			Role: ws.Role,
			Type: ws.Type,
		}
		merged[ws.ID] = entry

		old, existed := current[ws.ID]
		switch {
		case !existed:
			result.Added = append(result.Added, ws.Name)
		case old.Name != ws.Name || old.Role != ws.Role || old.Type != ws.Type:
			result.Changed = append(result.Changed, ws.Name)
		}
	}

	for id, old := range current {
		if _, stillThere := merged[id]; !stillThere {
			result.Removed = append(result.Removed, old.Name)
		}
	}

	return merged, result
}
