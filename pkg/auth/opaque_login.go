package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/opaque"
)

// OpaqueLogin authenticates with an OPAQUE (RFC 9807) exchange instead of a raw
// password. The password never leaves the device; it only derives the session
// key locally. The server's login/finish returns the same key material as a
// password login, so the post-auth storage path is shared via completeLogin.
//
// Flow:
//  1. LoginStart(password) -> KE1
//  2. POST /auth/opaque/login/start/ {email, ke1, credential_id} -> KE2, server_state
//  3. LoginFinish(client, KE2, credential_id) -> KE3, sessionKey
//  4. POST /auth/opaque/login/finish/ {email, ke3, server_state, credential_id}
//     -> login response (tokens + key material)
//  5. completeLogin stores the session exactly like PerformLogin.
func (s *Service) OpaqueLogin(email, password string) (*LoginResult, error) {
	credID := email // stable per-account id used as the OPAQUE credential id

	client, ke1, err := opaque.LoginStart(password)
	if err != nil {
		return nil, fmt.Errorf("opaque login: %w", err)
	}

	startResp, err := s.API.Call("auth.opaque_login_start", "POST", map[string]string{
		"email":         email,
		"ke1":           opaque.EncodeB64(ke1),
		"credential_id": credID,
	}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("opaque login start: %w", err)
	}
	defer startResp.Body.Close()
	if startResp.StatusCode != http.StatusOK {
		return nil, s.API.DecodeError(startResp)
	}
	var startData struct {
		Data struct {
			KE2         string `json:"ke2"`
			ServerState string `json:"server_state"`
		} `json:"data"`
	}
	if err := json.NewDecoder(startResp.Body).Decode(&startData); err != nil {
		return nil, fmt.Errorf("opaque login start: parse: %w", err)
	}

	ke3, _, exportKey, err := opaque.LoginFinishWithExport(client, startData.Data.KE2, credID)
	if err != nil {
		return nil, fmt.Errorf("opaque login: %w", err)
	}

	finishResp, err := s.API.Call("auth.opaque_login_finish", "POST", map[string]string{
		"email":         email,
		"ke3":           opaque.EncodeB64(ke3),
		"server_state":  startData.Data.ServerState,
		"credential_id": credID,
	}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("opaque login finish: %w", err)
	}
	defer finishResp.Body.Close()
	if finishResp.StatusCode != http.StatusOK {
		return nil, s.API.DecodeError(finishResp)
	}

	var loginResp loginResponse
	if err := json.NewDecoder(finishResp.Body).Decode(&loginResp); err != nil {
		return nil, fmt.Errorf("opaque login finish: parse: %w", err)
	}

	if err := config.SetOpaqueEnrolled(true); err != nil {
		return nil, fmt.Errorf("opaque login: %w", err)
	}
	result, err := s.completeLogin(email, password, nil, nil, &loginResp, loginOptions{
		ExportKey:     exportKey,
		ServerVaultV2: s.ServerSupportsVaultV2(),
	})
	if err != nil {
		return nil, err
	}
	// The session authenticated through OPAQUE, so enrollment must not run
	// again; re-enrolling would rotate the server-side record.
	result.OpaqueAuthenticated = true
	return result, nil
}

// EnrollOpaque upgrades an already-authenticated account to OPAQUE. It runs once,
// after the first v4 password login, and is idempotent on the client: the local
// OpaqueEnrolled flag prevents re-enrollment (which would rotate the record).
//
// Flow:
//  1. RegisterStart(password) -> reg_request
//  2. POST /auth/opaque/register/start/ {reg_request, credential_id} -> reg_response
//  3. RegisterFinish(client, reg_response, credential_id) -> record
//  4. POST /auth/opaque/register/finish/ (JWT) {reg_record, credential_id}
//     -> server stores the record and disables the password factor.
func (s *Service) EnrollOpaque(email, password string) error {
	credID := email

	client, regStart, err := opaque.RegisterStart(password)
	if err != nil {
		return fmt.Errorf("opaque enroll: %w", err)
	}

	startResp, err := s.API.Call("auth.opaque_register_start", "POST", map[string]string{
		"reg_request":   opaque.EncodeB64(regStart),
		"credential_id": credID,
	}, nil, nil)
	if err != nil {
		return fmt.Errorf("opaque enroll start: %w", err)
	}
	defer startResp.Body.Close()
	if startResp.StatusCode != http.StatusOK {
		return s.API.DecodeError(startResp)
	}
	var startData struct {
		Data struct {
			RegResponse  string `json:"reg_response"`
			CredentialID string `json:"credential_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(startResp.Body).Decode(&startData); err != nil {
		return fmt.Errorf("opaque enroll start: parse: %w", err)
	}

	regResp, err := opaque.DecodeB64(startData.Data.RegResponse)
	if err != nil {
		return fmt.Errorf("opaque enroll start: decode reg_response: %w", err)
	}
	record, err := opaque.RegisterFinish(client, regResp, credID)
	if err != nil {
		return fmt.Errorf("opaque enroll finish: %w", err)
	}

	// register/finish is JWT-protected; the API client adds the stored token.
	if err := s.API.CallNoContent("auth.opaque_register_finish", "POST", map[string]string{
		"reg_record":    opaque.EncodeB64(record),
		"credential_id": credID,
	}, nil, nil, http.StatusOK); err != nil {
		return fmt.Errorf("opaque enroll finish: %w", err)
	}

	if err := config.SetOpaqueEnrolled(true); err != nil {
		return fmt.Errorf("opaque enroll: %w", err)
	}
	return nil
}

// ServerSupportsOpaque reports whether the control plane has an OPAQUE sidecar
// reachable. Used to decide whether to attempt enrollment after a password login.
func (s *Service) ServerSupportsOpaque() bool {
	resp, err := s.API.Call("auth.capabilities", "GET", nil, nil, nil)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var capResp struct {
		Data struct {
			Opaque bool `json:"opaque"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&capResp); err != nil {
		return false
	}
	return capResp.Data.Opaque
}

// ServerSupportsVaultV2 reports whether the control plane accepts the v2
// split-share vault. The client gates the v1 -> v2 migration on it so a server
// can hold migration back during rollout without a client release.
func (s *Service) ServerSupportsVaultV2() bool {
	resp, err := s.API.Call("auth.capabilities", "GET", nil, nil, nil)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var capResp struct {
		Data struct {
			VaultV2 bool `json:"vault_v2"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&capResp); err != nil {
		return false
	}
	return capResp.Data.VaultV2
}

// isOPAQUEPasswordDisabled reports whether err is the server's signal that the
// account is enrolled and has no password factor.
func isOPAQUEPasswordDisabled(err error) bool {
	var ce *errors.CLIError
	if e, ok := err.(*errors.CLIError); ok {
		ce = e
	}
	if ce == nil {
		return false
	}
	return ce.Code == errors.ErrOPAQUEPasswordDisabled
}

// Login authenticates with email+password, transparently using the OPAQUE
// exchange when the account is enrolled (its password factor is disabled). It is
// the single entry point commands should use; raw PerformLogin is only correct
// when OPAQUE is known to be unavailable (e.g. signup, which creates the
// password factor).
func (s *Service) Login(email, password string) (*LoginResult, error) {
	result, err := s.PerformLogin(email, password, nil, nil)
	if err != nil && isOPAQUEPasswordDisabled(err) {
		return s.OpaqueLogin(email, password)
	}
	return result, err
}
