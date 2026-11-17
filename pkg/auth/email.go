package auth

import (
	"fmt"
	"net/http"

	"github.com/The-17/agentsecrets/pkg/config"
)

// UpdateEmail requests a verified email change. The server stores the pending
// address and sends a code to it. Delivery is wired through Brevo; until the
// server has BREVO_API_KEY set, the request fails closed (the server returns a
// clear "email delivery not configured" message).
func (s *Service) UpdateEmail(newEmail string) error {
	if config.GetEmail() == "" {
		return fmt.Errorf("update email: not logged in")
	}
	body := map[string]interface{}{"new_email": newEmail}
	if err := s.API.CallNoContent("auth.update_email", "POST", body, nil, nil, http.StatusOK); err != nil {
		return fmt.Errorf("update email: %w", err)
	}
	return nil
}

// ConfirmEmail completes the pending email change by proving the code that was
// sent to the new address.
func (s *Service) ConfirmEmail(newEmail string, otp int) error {
	if config.GetEmail() == "" {
		return fmt.Errorf("confirm email: not logged in")
	}
	body := map[string]interface{}{"new_email": newEmail, "otp": otp}
	if err := s.API.CallNoContent("auth.confirm_email", "POST", body, nil, nil, http.StatusOK); err != nil {
		return fmt.Errorf("confirm email: %w", err)
	}
	return nil
}

// ChangeEmailWithOpaque confirms a pending email change and, for an
// OPAQUE-enrolled account, keeps OPAQUE and the v2 vault consistent with the new
// address.
//
// The credential id is derived from the email, so re-enrolling under the new
// address rotates the OPAQUE export key. A v2 vault's opaque share is wrapped
// under that key. The old key and the Vault Key must therefore be captured
// BEFORE the server swaps the address, then the shares re-wrapped under the new
// key. Skip that and the next OPAQUE login cannot reconstruct the Vault Key,
// leaving the recovery key as the only way back in.
func (s *Service) ChangeEmailWithOpaque(newEmail string, otp int, password string) error {
	if !config.GetOpaqueEnrolled() {
		return s.ConfirmEmail(newEmail, otp)
	}

	oldEmail := config.GetEmail()
	userID := config.GetUserID()

	v, version, _, err := s.fetchVault(userID)
	if err != nil {
		return fmt.Errorf("change email: %w", err)
	}

	var oldExportKey, vaultKey []byte
	if v != nil && v.IsSplit() {
		oldExportKey, err = s.DeriveOpaqueExportKey(oldEmail, password)
		if err != nil {
			return fmt.Errorf("change email: %w", err)
		}
		vaultKey, err = v.UnlockWithShares(userID, password, oldExportKey)
		if err != nil {
			return fmt.Errorf("change email: unlock vault: %w", err)
		}
	}

	if err := s.ConfirmEmail(newEmail, otp); err != nil {
		return err
	}

	newExportKey, err := s.EnrollOpaque(newEmail, password)
	if err != nil {
		return fmt.Errorf("change email: OPAQUE re-link failed: %w", err)
	}

	if v != nil && v.IsSplit() && len(vaultKey) > 0 && len(newExportKey) > 0 {
		if err := v.RotateShares(userID, vaultKey, password, newExportKey); err != nil {
			return fmt.Errorf("change email: re-wrap vault shares: %w", err)
		}
		v.BumpVersion()
		if err := v.Sign(userID, vaultKey); err != nil {
			return fmt.Errorf("change email: re-sign vault: %w", err)
		}
		if err := s.putVault(v, version); err != nil {
			return fmt.Errorf("change email: save re-wrapped vault: %w", err)
		}
	}

	clear(oldExportKey)
	clear(vaultKey)
	clear(newExportKey)
	return nil
}

// VerifyEmail proves control of the account address with the code sent at
// signup. Verification is what unlocks cloud mode and lifts the free caps.
func (s *Service) VerifyEmail(otp int) error {
	if config.GetEmail() == "" {
		return fmt.Errorf("verify email: not logged in")
	}
	body := map[string]interface{}{"email": config.GetEmail(), "otp": otp}
	if err := s.API.CallNoContent("auth.verify_email", "POST", body, nil, nil, http.StatusOK); err != nil {
		return fmt.Errorf("verify email: %w", err)
	}
	return nil
}

// ResendVerification sends a fresh code to the account address.
func (s *Service) ResendVerification() error {
	if config.GetEmail() == "" {
		return fmt.Errorf("resend verification: not logged in")
	}
	body := map[string]interface{}{"email": config.GetEmail()}
	if err := s.API.CallNoContent("auth.resend_otp", "POST", body, nil, nil, http.StatusOK); err != nil {
		return fmt.Errorf("resend verification: %w", err)
	}
	return nil
}
