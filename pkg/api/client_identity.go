package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxIdentityResponseBytes caps how much of an identity response the client will
// buffer. The payload is small metadata; a larger body is treated as a hostile
// response and refused rather than parsed.
const maxIdentityResponseBytes = 64 << 10 // 64 KiB

// WorkloadIdentity is the resolver's self-description of the calling workload
// token. It carries entitlement metadata only — never a secret value or key name.
type WorkloadIdentity struct {
	IdentityLevel  string   `json:"identity_level"`
	WorkspaceID    string   `json:"workspace_id"`
	ProjectID      string   `json:"project_id,omitempty"`
	WorkspaceWide  bool     `json:"workspace_wide"`
	Environment    string   `json:"environment"`
	TokenID        string   `json:"token_id"`
	AgentID        string   `json:"agent_id"`
	Scopes         []string `json:"scopes"`
	AgentScopes    []string `json:"agent_scopes"`
	Attenuated     []string `json:"attenuated,omitempty"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	CanDo          []string `json:"can_do"`
}

// FetchWorkloadIdentity asks the Go resolver to describe the calling workload
// token (POST /v1/identity): its binding triple, effective scopes, agent ceiling,
// and plain-English "what I can do". It is the answer to "who am I running as".
//
// No secret values cross this path. The caller's context bounds the request, so
// an unreachable resolver degrades quickly instead of hanging the caller.
func FetchWorkloadIdentity(ctx context.Context, resolverURL, token string) (*WorkloadIdentity, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("invalid workload token: token is empty")
	}
	if strings.TrimSpace(resolverURL) == "" {
		return nil, fmt.Errorf("resolver URL is empty")
	}

	targetURL := strings.TrimRight(resolverURL, "/") + "/v1/identity"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{
		Timeout: 15 * time.Second,
		// A redirect is data from an untrusted peer, not an instruction to fetch
		// another location. Following one lets a hostile resolver point the client
		// at an internal or metadata endpoint (client-side SSRF).
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error contacting cloud resolver: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("resolver returned a redirect (%d); refusing to follow it", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		if detail := decodeDetail(resp); detail != "" {
			return nil, fmt.Errorf("%s", detail)
		}
		return nil, fmt.Errorf("authentication failed: invalid, expired, or revoked workload token")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, decodeDetail(resp))
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxIdentityResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read identity response: %w", err)
	}
	if int64(len(raw)) > maxIdentityResponseBytes {
		return nil, fmt.Errorf("identity response exceeds %d bytes; refusing to buffer it", maxIdentityResponseBytes)
	}

	var id WorkloadIdentity
	if err := json.Unmarshal(raw, &id); err != nil {
		return nil, fmt.Errorf("failed to parse identity response: %w", err)
	}
	return &id, nil
}
