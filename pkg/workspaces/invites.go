package workspaces

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/The-17/agentsecrets/pkg/config"
)

// PendingInvite is an invitation waiting on the signed-in address. It grants
// nothing until accepted.
type PendingInvite struct {
	ID            string `json:"id"`
	WorkspaceID   string `json:"workspace_id"`
	WorkspaceName string `json:"workspace_name"`
	Role          string `json:"role"`
	InvitedBy     string `json:"invited_by"`
	ExpiresAt     string `json:"expires_at"`
}

// AcceptResult describes the workspace the invitation opened.
type AcceptResult struct {
	WorkspaceID   string `json:"workspace_id"`
	WorkspaceName string `json:"workspace_name"`
	Role          string `json:"role"`
	// KeyPending is true until an admin client seals the workspace key. The
	// workspace is listed but nothing in it resolves until then.
	KeyPending bool `json:"key_pending"`
}

type awaitingKeyInvite struct {
	WorkspaceID   string `json:"workspace_id"`
	WorkspaceName string `json:"workspace_name"`
	Email         string `json:"email"`
	Role          string `json:"role"`
}

// PendingInvites lists invitations addressed to the signed-in account.
func (s *Service) PendingInvites() ([]PendingInvite, error) {
	if config.GetEmail() == "" {
		return nil, fmt.Errorf("not logged in")
	}

	resp, err := s.API.Call("invites.pending", "GET", nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("list pending invites: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, s.API.DecodeError(resp)
	}

	var res struct {
		Data []PendingInvite `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("list pending invites: invalid response: %w", err)
	}
	return res.Data, nil
}

// AcceptInvite redeems an invitation with either the link token or the
// six-digit code. The signed-in address must be the invited address; the
// server enforces that and gives the same answer when it is not.
func (s *Service) AcceptInvite(token, code, workspaceID string) (*AcceptResult, error) {
	if config.GetEmail() == "" {
		return nil, fmt.Errorf("not logged in")
	}
	if token == "" && code == "" {
		return nil, fmt.Errorf("accept invite: a link token or a code is required")
	}

	body := map[string]any{}
	if token != "" {
		body["token"] = token
	}
	if code != "" {
		body["code"] = code
	}
	if workspaceID != "" {
		body["workspace_id"] = workspaceID
	}

	resp, err := s.API.Call("invites.accept", "POST", body, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("accept invite: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, s.API.DecodeError(resp)
	}

	var res struct {
		Data AcceptResult `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("accept invite: invalid response: %w", err)
	}
	return &res.Data, nil
}

// FinalizeAcceptedInvites seals the workspace key for people who accepted an
// invitation while this client was away.
//
// The server cannot do this: it never holds a plaintext workspace key, and a
// brand-new account has no public key at invite time. So the admin's client
// is the only party that can finish the handoff. It runs on refresh, which is
// the moment the admin is already talking to the server.
//
// Failures are returned, not swallowed: a member left locked needs to know.
func (s *Service) FinalizeAcceptedInvites() (sealed []string, failures []string, err error) {
	if config.GetEmail() == "" {
		return nil, nil, nil
	}

	resp, err := s.API.Call("invites.awaiting_key", "GET", nil, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("finalize invites: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, s.API.DecodeError(resp)
	}

	var res struct {
		Data []awaitingKeyInvite `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, nil, fmt.Errorf("finalize invites: invalid response: %w", err)
	}

	for _, invite := range res.Data {
		results, err := s.InviteBatch(invite.WorkspaceID, []string{invite.Email}, invite.Role)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s (%s): %v", invite.Email, invite.WorkspaceName, err))
			continue
		}
		if len(results) > 0 && results[0].Error != "" {
			failures = append(failures, fmt.Sprintf("%s (%s): %s", invite.Email, invite.WorkspaceName, results[0].Error))
			continue
		}
		sealed = append(sealed, fmt.Sprintf("%s (%s)", invite.Email, invite.WorkspaceName))
	}
	return sealed, failures, nil
}
