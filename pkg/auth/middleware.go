package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/telemetry"
	"github.com/The-17/agentsecrets/pkg/ui"
)

// missingSessionError explains a session that is not usable on this machine.
//
// When the account is still configured but no token can be found, the token was
// not invalidated: it is absent from the credential store. That is what a
// replaced keychain looks like (installing the system-wide daemon moves the store
// to a different user), and telling the user their session is "invalid, revoked,
// or expired" sends them looking for a cause that does not exist.
func missingSessionError(email string) error {
	if email == "" {
		return errors.New(errors.ErrUnauthorized, "you must be logged in to perform this action", nil)
	}
	return errors.New(
		errors.ErrUnauthorized,
		fmt.Sprintf("this machine has no usable session for %s", email),
		fmt.Errorf("the account is still configured, but its saved session is not in the credential store. That happens when the store is replaced, for example after installing the system-wide keychain-auth daemon. Run 'agentsecrets login' to sign in again"),
	)
}

// EnsureAuth is a Cobra PersistentPreRunE middleware that checks session validity.
// It automatically refreshes the access token if it is expired or close to expiring,
// assuming a valid refresh token exists.
func (s *Service) EnsureAuth(cmd *cobra.Command, args []string) error {
	if !config.IsAuthenticated() {
		return missingSessionError(config.GetEmail())
	}

	if config.IsTokenExpired() {
		tokens, err := config.LoadTokens()
		if err != nil || tokens == nil || tokens.RefreshToken == "" {
			// No refresh token can renew this session, so login is required.
			return errors.New(errors.ErrUnauthorized, "your session expired and no refresh token is stored to renew it automatically. Run 'agentsecrets login' to sign in again.", nil)
		}
		// A refresh token exists: renew silently. Only if the server rejects it
		// is a fresh login actually required, and then we say exactly that.
		if err := ui.Spinner("Refreshing expired session token...", func() error {
			return s.RefreshSession(tokens.RefreshToken)
		}); err != nil {
			return errors.New(errors.ErrUnauthorized, "your session expired and the stored refresh token was rejected. Run 'agentsecrets login' to sign in again.", err)
		}
	}

	return nil
}

// refreshResponse represents token refresh API response
type refreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    string `json:"expires_at"`
	Data         struct {
		Access    string `json:"access"`
		Refresh   string `json:"refresh"`
		ExpiresAt string `json:"expires_at"`
	} `json:"data"`
}

// RefreshSession uses the refresh token to get a new access token.
func (s *Service) RefreshSession(refreshToken string) error {
	if refreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	data := map[string]string{
		"refresh": refreshToken,
	}

	start := time.Now()
	resp, err := s.API.Call("auth.refresh", "POST", data, nil, nil)
	duration := time.Since(start).Milliseconds()
	telemetry.RecordSessionRefreshMs(duration)

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return s.API.DecodeError(resp)
	}

	var res refreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return fmt.Errorf("failed to parse refresh response: %w", err)
	}

	access := coalesce(res.AccessToken, res.Data.Access)
	if access == "" {
		return fmt.Errorf("no access token in refresh response")
	}

	newRefresh := coalesce(res.RefreshToken, res.Data.Refresh)
	if newRefresh == "" {
		newRefresh = refreshToken // Keep old one if not rotated
	}

	expiresAt := coalesce(res.ExpiresAt, res.Data.ExpiresAt)
	if expiresAt == "" {
		// Fallback: estimate
		expiresAt = time.Now().Add(10 * time.Minute).Format(time.RFC3339)
	}

	return config.StoreTokens(access, newRefresh, expiresAt)
}
