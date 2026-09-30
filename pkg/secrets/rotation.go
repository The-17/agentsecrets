// Package secrets rotation implements the B1 client-push value rotation flow:
// stage a client-encrypted pending version, promote it to current after the
// operator updates the downstream provider, and roll back when needed. The
// CLI holds the workspace DEK, so it is the DEK-holder that produces every
// new ciphertext; the server only ever stores ciphertext.
package secrets

import (
	"fmt"
	"strings"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/google/uuid"
)

// StagedVersion is a pending version awaiting promotion.
type StagedVersion struct {
	VersionID  string `json:"version_id"`
	Staging    string `json:"staging_label"`
	Reason     string `json:"rotation_reason"`
	RotationID string `json:"rotation_id,omitempty"`
	CreatedAt  string `json:"created_at"`
	Replayed   bool   `json:"replayed"`
}

// PromoteResult is returned after a successful promote or rollback.
type PromoteResult struct {
	Key               string `json:"key"`
	Environment       string `json:"environment"`
	CurrentVersionID  string `json:"current_version_id"`
	PreviousVersionID string `json:"previous_version_id,omitempty"`
	Reason            string `json:"reason,omitempty"`
}

// VersionInfo is rotation metadata for one archived version (no ciphertext).
type VersionInfo struct {
	VersionID string `json:"version_id"`
	Staging   string `json:"staging_label"`
	Reason    string `json:"rotation_reason"`
	CreatedAt string `json:"created_at"`
	Overlap   string `json:"overlap_until,omitempty"`
	RevokedAt string `json:"revoked_at,omitempty"`
}

// RotationStatus describes a secret's cadence and version history.
type RotationStatus struct {
	Key         string         `json:"key"`
	Environment string         `json:"environment"`
	Policy      map[string]any `json:"policy"`
	Versions    []VersionInfo  `json:"versions"`
}

// RotationPolicy arms or disarms a value-rotation cadence (desired-state;
// execution is Pro-gated in the resolver).
type RotationPolicy struct {
	Type         string         `json:"rotation_type,omitempty"`
	PeriodDays   *int           `json:"period_days,omitempty"`
	OverlapHours *int           `json:"overlap_hours,omitempty"`
	Binding      map[string]any `json:"provider_binding,omitempty"`
	Enabled      bool           `json:"enabled"`
}

// resolveRotationTarget loads the project and environment for rotation calls.
func (s *Service) resolveRotationTarget(key, environment string) (projectID, env, upperKey string, err error) {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return "", "", "", fmt.Errorf("rotation: no project configured in current directory")
	}
	env = environment
	if env == "" {
		env = config.ResolveEnvironment()
	}
	return project.ProjectID, env, strings.ToUpper(key), nil
}

// StageVersion encrypts a new plaintext value with the workspace DEK and
// stages it as pending. The returned rotation ID makes retries idempotent.
func (s *Service) StageVersion(key, plaintext, environment, reason string) (*StagedVersion, string, error) {
	projectID, env, upperKey, err := s.resolveRotationTarget(key, environment)
	if err != nil {
		return nil, "", err
	}
	workspaceKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return nil, "", fmt.Errorf("rotation: %w", err)
	}
	ciphertext, err := crypto.EncryptSecret(plaintext, workspaceKey)
	if err != nil {
		return nil, "", fmt.Errorf("rotation: encryption failed for %s: %w", upperKey, err)
	}
	rotationID := "cli-" + uuid.NewString()
	reqReason := reason
	if reqReason == "" {
		reqReason = "routine"
	}
	resp, err := api.CallJSON[StagedVersion](s.API, "secrets.rotate_stage", "POST", map[string]any{
		"ciphertext":  ciphertext,
		"rotation_id": rotationID,
		"reason":      reqReason,
	}, map[string]string{
		"project_id":  projectID,
		"environment": env,
		"key":         upperKey,
	}, nil)
	if err != nil {
		return nil, "", err
	}
	return &resp, rotationID, nil
}

// PromoteVersion flips the staged pending version to current. Reason
// "compromise" shreds previous ciphertext immediately (zero overlap).
func (s *Service) PromoteVersion(key, environment, expectedCurrentID, reason string) (*PromoteResult, error) {
	projectID, env, upperKey, err := s.resolveRotationTarget(key, environment)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"reason": reason}
	if expectedCurrentID != "" {
		body["expected_current_version_id"] = expectedCurrentID
	}
	resp, err := api.CallJSON[PromoteResult](s.API, "secrets.rotate_promote", "POST", body, map[string]string{
		"project_id":  projectID,
		"environment": env,
		"key":         upperKey,
	}, nil)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// RollbackVersion restores the previous value to current. Refused when the
// previous was poisoned by a compromise rotation or reaped by retention.
func (s *Service) RollbackVersion(key, environment string) (*PromoteResult, error) {
	projectID, env, upperKey, err := s.resolveRotationTarget(key, environment)
	if err != nil {
		return nil, err
	}
	resp, err := api.CallJSON[PromoteResult](s.API, "secrets.rotate_rollback", "POST", nil, map[string]string{
		"project_id":  projectID,
		"environment": env,
		"key":         upperKey,
	}, nil)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// AbortPending deletes a staged pending version, unsticking a crashed rotation.
func (s *Service) AbortPending(key, environment string) error {
	projectID, env, upperKey, err := s.resolveRotationTarget(key, environment)
	if err != nil {
		return err
	}
	return s.API.CallNoContent("secrets.rotate_abort", "DELETE", nil, map[string]string{
		"project_id":  projectID,
		"environment": env,
		"key":         upperKey,
	}, nil)
}

// RotationStatus fetches a secret's cadence and version history (metadata only).
func (s *Service) RotationStatus(key, environment string) (*RotationStatus, error) {
	projectID, env, upperKey, err := s.resolveRotationTarget(key, environment)
	if err != nil {
		return nil, err
	}
	resp, err := api.CallJSON[RotationStatus](s.API, "secrets.rotation_status", "GET", nil, map[string]string{
		"project_id":  projectID,
		"environment": env,
		"key":         upperKey,
	}, nil)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// SetRotationPolicy arms or disarms a value-rotation cadence.
func (s *Service) SetRotationPolicy(key, environment string, policy RotationPolicy) error {
	projectID, env, upperKey, err := s.resolveRotationTarget(key, environment)
	if err != nil {
		return err
	}
	return s.API.CallNoContent("secrets.rotation_policy", "PUT", policy, map[string]string{
		"project_id":  projectID,
		"environment": env,
		"key":         upperKey,
	}, nil)
}
