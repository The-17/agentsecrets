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
