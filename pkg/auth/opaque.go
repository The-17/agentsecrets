package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/The-17/agentsecrets/pkg/opaque"
)

// Capabilities is the public server advertisement of auth methods.
type Capabilities struct {
	Password    bool `json:"password"`
	Opaque      bool `json:"opaque"`
	OAuthGitHub bool `json:"oauth_github"`
	OAuthGoogle bool `json:"oauth_google"`
	EmailLink   bool `json:"email_link"`
}

// FetchCapabilities reads /auth/capabilities/. An old server 404s, which is
// reported as "no capabilities", not as an error.
func (s *Service) FetchCapabilities() (*Capabilities, error) {
	resp, err := s.API.Call("auth.capabilities", "GET", nil, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return &Capabilities{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, s.API.DecodeError(resp)
	}
	var env struct {
		Data Capabilities `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("capabilities: %w", err)
	}
	return &env.Data, nil
}

// EnrollOpaque registers this account's password with OPAQUE and returns once
// the server has stored the record. The password itself never crosses the
// wire: only blinded registration messages do.
func (s *Service) EnrollOpaque(email, password string) error {
	credentialID := opaqueCredentialID(email)

	client, regStart, err := opaque.RegisterStart(password)
	if err != nil {
		return err
	}
	startResp, err := s.API.Call("auth.opaque_register_start", "POST", map[string]string{
		"reg_request":   opaque.EncodeB64(regStart),
		"credential_id": credentialID,
	}, nil, nil)
	if err != nil {
		return fmt.Errorf("opaque enroll: %w", err)
	}
	defer startResp.Body.Close()
	if startResp.StatusCode != http.StatusOK {
		return fmt.Errorf("opaque enroll: %w", s.API.DecodeError(startResp))
	}
	var startEnv struct {
		Data struct {
			RegResponse string `json:"reg_response"`
		} `json:"data"`
	}
	if err := json.NewDecoder(startResp.Body).Decode(&startEnv); err != nil {
		return fmt.Errorf("opaque enroll: parse start response: %w", err)
	}
	regResponse, err := opaque.DecodeB64(startEnv.Data.RegResponse)
	if err != nil {
		return fmt.Errorf("opaque enroll: %w", err)
	}
	record, err := opaque.RegisterFinish(client, regResponse, credentialID)
	if err != nil {
		return err
	}
	finishResp, err := s.API.Call("auth.opaque_register_finish", "POST", map[string]string{
		"reg_record":    opaque.EncodeB64(record),
		"credential_id": credentialID,
	}, nil, nil)
	if err != nil {
		return fmt.Errorf("opaque enroll: %w", err)
	}
	defer finishResp.Body.Close()
	if finishResp.StatusCode != http.StatusOK {
		return fmt.Errorf("opaque enroll: %w", s.API.DecodeError(finishResp))
	}
	return nil
}

// opaqueLogin performs the OPAQUE exchange and returns the server's login
// payload. It is used when password login reports that the account is enrolled.
func (s *Service) opaqueLogin(email, password string) (*loginResponse, error) {
	credentialID := opaqueCredentialID(email)
	client, ke1, err := opaque.LoginStart(password)
	if err != nil {
		return nil, err
	}
	startResp, err := s.API.Call("auth.opaque_login_start", "POST", map[string]string{
		"email":         email,
		"ke1":           opaque.EncodeB64(ke1),
		"credential_id": credentialID,
	}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("opaque login: %w", err)
	}
	defer startResp.Body.Close()
	if startResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("opaque login: %w", s.API.DecodeError(startResp))
	}
	var startEnv struct {
		Data struct {
			KE2         string `json:"ke2"`
			ServerState string `json:"server_state"`
		} `json:"data"`
	}
	if err := json.NewDecoder(startResp.Body).Decode(&startEnv); err != nil {
		return nil, fmt.Errorf("opaque login: parse start response: %w", err)
	}

	ke3, _, err := opaque.LoginFinish(client, startEnv.Data.KE2, credentialID)
	if err != nil {
		return nil, fmt.Errorf("opaque login: wrong password or tampered server response: %w", err)
	}
	finishResp, err := s.API.Call("auth.opaque_login_finish", "POST", map[string]string{
		"email":         email,
		"ke3":           opaque.EncodeB64(ke3),
		"server_state":  startEnv.Data.ServerState,
		"credential_id": credentialID,
	}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("opaque login: %w", err)
	}
	defer finishResp.Body.Close()
	if finishResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("opaque login: %w", s.API.DecodeError(finishResp))
	}
	var out loginResponse
	if err := json.NewDecoder(finishResp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("opaque login: parse response: %w", err)
	}
	return &out, nil
}

// opaqueCredentialID derives a stable id from the account email. It must not
// change between enrollment and login: the server binds the record and the
// masking nonce to it, so a different value fails the exchange by design.
//
// It is a UUIDv5 over the email rather than the email itself so the raw address
// is not handed to the sidecar, which only needs an opaque identifier.
func opaqueCredentialID(email string) string {
	return uuid.NewSHA1(opaqueCredentialNamespace, []byte(strings.ToLower(email))).String()
}

// opaqueCredentialNamespace is a fixed namespace for credential ids. Changing it
// orphans every enrolled account, so it is a hard-coded constant, not a config.
var opaqueCredentialNamespace = uuid.MustParse("6f9619ff-8b86-d011-b42d-00c04fc964ff")
