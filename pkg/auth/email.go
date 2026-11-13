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
