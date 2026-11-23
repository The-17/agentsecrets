package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/The-17/agentsecrets/pkg/proxy"
)

func postSessionEndpoint(port int, path, token string) ([]byte, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d%s", port, path)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build %s request: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AS-Session-Token", token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("proxy daemon is not reachable on port %d: %w", port, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s response: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy rejected %s: %s", path, string(body))
	}
	return body, nil
}

// requestSessionTokenRotation asks the daemon to generate and install a new
// session token. The token is generated server-side so a caller cannot choose
// the session key.
func requestSessionTokenRotation(port int, oldToken string) (string, error) {
	body, err := postSessionEndpoint(port, "/rotate-session", oldToken)
	if err != nil {
		return "", err
	}
	var response struct {
		NewToken string `json:"new_token"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to decode rotation response: %w", err)
	}
	if response.NewToken == "" {
		return "", fmt.Errorf("proxy returned no new session token")
	}
	return response.NewToken, nil
}

// rollbackSessionToken restores the previous token after a failed local write.
// It authenticates with the new token, so only a caller that received the
// rotation response can undo it.
func rollbackSessionToken(port int, newToken string) error {
	_, err := postSessionEndpoint(port, "/rollback-session", newToken)
	return err
}

// rotateProxySession keeps the daemon and the keyring on the same token. If
// the keyring write fails, the daemon is rolled back before the error is
// reported. Previously the daemon kept the new token while the keyring kept
// the old one, so every later call was a 401 with no local clue why.
func rotateProxySession(port int) error {
	oldToken, err := proxy.ReadSessionToken()
	if err != nil {
		return fmt.Errorf("failed to read current session token: %w", err)
	}

	newToken, err := requestSessionTokenRotation(port, oldToken)
	if err != nil {
		return err
	}

	if err := proxy.WriteSessionToken(newToken); err != nil {
		if rbErr := rollbackSessionToken(port, newToken); rbErr != nil {
			return fmt.Errorf("new session token was generated but could not be stored (%v), and automatic rollback failed (%v); restart the proxy daemon and retry", err, rbErr)
		}
		return fmt.Errorf("could not store the new session token (%v); the daemon was rolled back to the previous token, so retry the rotation", err)
	}
	return nil
}
