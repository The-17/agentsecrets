// Package auth — OAuth sign-in with Google and GitHub.
//
// The flow is Authorization Code with a loopback redirect:
//
//  1. Ask the server for the provider authorize URL and a signed state.
//  2. Open the browser; the provider redirects back to 127.0.0.1:53682.
//  3. Exchange the code through the server, which holds the client secret.
//  4. Store the session.
//
// A social login proves identity, not possession of the vault key, so it does
// not unlock secrets on this device. The command says so instead of pretending
// otherwise. Existing password accounts keep their password method; the server
// links the social identity rather than replacing it.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/The-17/agentsecrets/pkg/config"
)

var (
	oauthLoopbackAddr = "127.0.0.1:53682"
	oauthRedirectURI  = "http://127.0.0.1:53682/callback"
)

const (
	oauthFlowTimeout  = 5 * time.Minute
	oauthCallbackPath = "/callback"
)

type oauthAuthorizeResponse struct {
	Data struct {
		AuthorizeURL string `json:"authorize_url"`
		State        string `json:"state"`
	} `json:"data"`
}

// OAuthLogin runs the browser loopback flow for provider ("google" or
// "github") and stores the resulting session.
func (s *Service) OAuthLogin(provider string) (*LoginResult, error) {
	if provider != "google" && provider != "github" {
		return nil, fmt.Errorf("unsupported sign-in provider %q", provider)
	}

	// 1. Ask the server for the authorize URL and signed state.
	resp, err := s.API.Call(
		"auth.oauth_authorize",
		"GET",
		nil,
		map[string]string{"provider": provider},
		map[string]string{"redirect_uri": oauthRedirectURI},
	)
	if err != nil {
		return nil, fmt.Errorf("oauth: authorize request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, s.API.DecodeError(resp)
	}
	var authResp oauthAuthorizeResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, fmt.Errorf("oauth: failed to parse authorize response: %w", err)
	}
	if authResp.Data.AuthorizeURL == "" || authResp.Data.State == "" {
		return nil, fmt.Errorf("oauth: server did not return an authorize URL (is %s enabled?)", provider)
	}

	// 2. Listen on the loopback callback before opening the browser.
	ln, err := net.Listen("tcp", oauthLoopbackAddr)
	if err != nil {
		return nil, fmt.Errorf("oauth: cannot listen on %s: %w", oauthLoopbackAddr, err)
	}

	type callback struct {
		code string
		err  error
	}
	resultCh := make(chan callback, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(oauthCallbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			msg := q.Get("error_description")
			if msg == "" {
				msg = e
			}
			http.Error(w, "Sign-in failed: "+msg, http.StatusBadRequest)
			select {
			case resultCh <- callback{err: fmt.Errorf("provider rejected sign-in: %s", msg)}:
			default:
			}
			return
		}
		if q.Get("state") != authResp.Data.State {
			http.Error(w, "Sign-in state mismatch.", http.StatusBadRequest)
			select {
			case resultCh <- callback{err: fmt.Errorf("oauth: state mismatch on callback")}:
			default:
			}
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "Sign-in did not return a code.", http.StatusBadRequest)
			select {
			case resultCh <- callback{err: fmt.Errorf("oauth: callback had no code")}:
			default:
			}
			return
		}
		fmt.Fprint(w, "<html><body><h3>Signed in to AgentSecrets.</h3><p>You can close this window and return to the terminal.</p></body></html>")
		select {
		case resultCh <- callback{code: code}:
		default:
		}
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	if err := openBrowser(authResp.Data.AuthorizeURL); err != nil {
		return nil, fmt.Errorf("oauth: could not open a browser: %w", err)
	}
	// 3. Wait for the provider to redirect back.
	var cb callback
	select {
	case cb = <-resultCh:
	case <-time.After(oauthFlowTimeout):
		return nil, fmt.Errorf("oauth: timed out waiting for the browser (5 minutes)")
	}
	if cb.err != nil {
		return nil, cb.err
	}

	// 4. Exchange the code through the server.
	exResp, err := s.API.Call(
		"auth.oauth_exchange",
		"POST",
		map[string]string{
			"code":         cb.code,
			"redirect_uri": oauthRedirectURI,
			"state":        authResp.Data.State,
		},
		map[string]string{"provider": provider},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("oauth: exchange failed: %w", err)
	}
	defer exResp.Body.Close()
	if exResp.StatusCode != http.StatusOK {
		return nil, s.API.DecodeError(exResp)
	}
	var login loginResponse
	if err := json.NewDecoder(exResp.Body).Decode(&login); err != nil {
		return nil, fmt.Errorf("oauth: failed to parse exchange response: %w", err)
	}

	// 5. Store the session. A social login carries no keypair or vault material.
	email := login.Data.User.Email
	if email != "" {
		if err := config.SetEmail(email); err != nil {
			return nil, fmt.Errorf("oauth: failed to save email: %w", err)
		}
	}
	if login.Data.User.ID != "" {
		if err := config.SetUserID(login.Data.User.ID); err != nil {
			return nil, fmt.Errorf("oauth: failed to save account id: %w", err)
		}
	}
	if err := config.StoreTokens(
		coalesce(login.AccessToken, login.Data.Access),
		coalesce(login.RefreshToken, login.Data.Refresh),
		coalesce(login.ExpiresAt, login.Data.ExpiresAt),
	); err != nil {
		return nil, fmt.Errorf("oauth: failed to save tokens: %w", err)
	}

	result := &LoginResult{HasKeys: login.Data.User.PublicKey != ""}
	if login.Data.User.PublicKey == "" {
		result.Warnings = append(result.Warnings,
			"Signed in with "+provider+". This device has no vault key yet, so secrets stay locked until you set a vault password.")
	}
	return result, nil
}

// openBrowser opens url in the platform default browser. It is a variable so
// tests can substitute a fake browser.
var openBrowser = func(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
