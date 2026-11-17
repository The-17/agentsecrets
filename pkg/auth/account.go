package auth

import (
	"fmt"
	"net/http"
	"os"

	"github.com/The-17/agentsecrets/pkg/config"
)

// UpdateProfile changes the account's display name.
func (s *Service) UpdateProfile(firstName, lastName string) error {
	if config.GetEmail() == "" {
		return fmt.Errorf("update profile: not logged in")
	}
	body := map[string]string{}
	if firstName != "" {
		body["first_name"] = firstName
	}
	if lastName != "" {
		body["last_name"] = lastName
	}
	if len(body) == 0 {
		return fmt.Errorf("update profile: nothing to change")
	}
	if err := s.API.CallNoContent("auth.update_profile", "PATCH", body, nil, nil, http.StatusOK); err != nil {
		return fmt.Errorf("update profile: %w", err)
	}
	return nil
}

// UploadAvatar posts a PNG/JPEG/WebP as the account avatar. The server caps it
// at 2 MB. The file contents never go anywhere except this request.
func (s *Service) UploadAvatar(path string) error {
	if config.GetEmail() == "" {
		return fmt.Errorf("upload avatar: not logged in")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("upload avatar: %w", err)
	}
	if err := s.API.CallMultipart("auth.upload_avatar", "file", path, content); err != nil {
		return fmt.Errorf("upload avatar: %w", err)
	}
	return nil
}

// DeactivateAccount signs out everywhere and stops new logins.
func (s *Service) DeactivateAccount() error {
	if config.GetEmail() == "" {
		return fmt.Errorf("deactivate account: not logged in")
	}
	if err := s.API.CallNoContent("auth.deactivate", "POST", nil, nil, nil, http.StatusOK); err != nil {
		return fmt.Errorf("deactivate account: %w", err)
	}
	return nil
}

// DeleteAccount permanently removes the account after an email confirmation.
func (s *Service) DeleteAccount(confirmEmail string) error {
	if config.GetEmail() == "" {
		return fmt.Errorf("delete account: not logged in")
	}
	body := map[string]string{"confirm_email": confirmEmail}
	if err := s.API.CallNoContent("auth.delete_account", "DELETE", body, nil, nil, http.StatusOK); err != nil {
		return fmt.Errorf("delete account: %w", err)
	}
	return nil
}
