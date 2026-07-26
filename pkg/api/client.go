// Package api provides the HTTP client for communicating with the AgentSecrets API.
//
// This package mirrors the Python SecretsCLI's api/client.py module.
// It handles all HTTP communication including authentication headers,
// endpoint resolution, and request/response handling.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/The-17/agentsecrets/pkg/errors"
)

// DefaultBaseURL is the SecretsCLI API endpoint
const DefaultBaseURL = "https://secrets-api-orpin.vercel.app/api"

// endpointMap defines all API routes, matching the Python ENDPOINT_MAP exactly
var endpointMap = map[string]map[string]string{
	"auth": {
		"signup":  "auth/register/",
		"login":   "auth/login/",
		"logout":  "auth/logout/",
		"refresh": "auth/refresh/",
	},
	"secrets": {
		"list":            "secrets/{project_id}/",
		"create":          "secrets/",
		"get":             "secrets/{project_id}/{environment}/{key}/",
		"update":          "secrets/{project_id}/{environment}/{key}/",
		"delete":          "secrets/{project_id}/{environment}/{key}/",
		"get_policy": "secrets/{project_id}/{environment}/{key}/policy/",
		"set_policy": "secrets/{project_id}/{environment}/{key}/policy/",
	},
	"projects": {
		"list":   "projects/",
		"create": "projects/",
		"get":    "projects/{workspace_id}/{project_name}/",
		"update": "projects/{workspace_id}/{project_name}/",
		"delete": "projects/{workspace_id}/{project_name}/",
		"invite": "projects/{workspace_id}/{project_name}/invite/",
	},
	"workspaces": {
		"list":             "workspaces/",
		"create":           "workspaces/",
		"get":              "workspaces/{workspace_id}/",
		"update":           "workspaces/{workspace_id}/",
		"delete":           "workspaces/{workspace_id}/",
		"members":          "workspaces/{workspace_id}/members/",
		"invite":           "workspaces/{workspace_id}/members/",
		"remove_member":    "workspaces/{workspace_id}/members/{user_id}/",
		"role_update":      "workspaces/{workspace_id}/members/{user_id}/role/",
		"allowlist_list":   "workspaces/{workspace_id}/allowlist/",
		"allowlist_add":    "workspaces/{workspace_id}/allowlist/",
		"allowlist_remove": "workspaces/{workspace_id}/allowlist/{domain}/",
		"allowlist_log":    "workspaces/{workspace_id}/allowlist/log/",
	},
	"agents": {
		"list":             "workspaces/{workspace_id}/agents/",
		"register":         "workspaces/{workspace_id}/agents/",
		"list_project":     "workspaces/{workspace_id}/projects/{project_id}/agents/",
		"register_project": "workspaces/{workspace_id}/projects/{project_id}/agents/",
		"delete":           "workspaces/{workspace_id}/agents/{registration_id}/",
		"token_issue":      "workspaces/{workspace_id}/agents/{registration_id}/tokens/",
		"token_list":       "workspaces/{workspace_id}/agents/{registration_id}/tokens/",
		"token_revoke":     "workspaces/{workspace_id}/agents/{registration_id}/tokens/{token_id}/",
		"get_capabilities": "workspaces/{workspace_id}/agents/{registration_id}/capabilities/",
		"set_capabilities": "workspaces/{workspace_id}/agents/{registration_id}/capabilities/",
		"token_validate":   "internal/agents/verify/",
	},
	"log": {
		"list":    "audit/logs/",
		"detail":  "audit/logs/{log_id}/",
		"summary": "audit/summary/",
		"export":  "audit/export/",
	},
	"audit": {
		"sync": "internal/audit/logs/",
	},
	"telemetry": {
		"sync": "/telemetry/sync/",
	},
	"users": {
		"public_key": "users/{email}/public-key/",
	},
}

// publicEndpoints are endpoints that don't require an auth token
var publicEndpoints = map[string]bool{
	"auth.signup":    true,
	"auth.login":     true,
	"auth.refresh":   true,
	"telemetry.sync": true,
}

// Client handles all HTTP communication with the AgentSecrets API server.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	// getToken is a function that returns the current access token.
	// This is injected so the API client doesn't depend on the config package directly.
	getToken  func() string
	refreshFn func() (string, error) // dynamic callback to refresh token
	refreshMu sync.Mutex             // guards token refresh to prevent concurrent refresh storms
}

// NewClient creates a new API client with the default base URL.
func NewClient(tokenFunc func() string) *Client {
	baseURL := DefaultBaseURL
	if envURL := os.Getenv("AGENTSECRETS_API_URL"); envURL != "" {
		baseURL = envURL
	}
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		getToken:   tokenFunc,
	}
}

// SetRefreshTokenCallback registers the callback used to dynamically refresh expired tokens.
func (c *Client) SetRefreshTokenCallback(f func() (string, error)) {
	c.refreshFn = f
}

// Call makes an API request to the specified endpoint.
//
// endpointKey uses dot notation like "auth.login" or "secrets.get".
// method is the HTTP method (GET, POST, PUT, DELETE).
// data is the request body (will be JSON-encoded), can be nil.
// urlParams are substituted into the endpoint path template.
// queryParams are added as ?key=value to the URL.
func (c *Client) Call(endpointKey, method string, data interface{}, urlParams map[string]string, queryParams map[string]string) (*http.Response, error) {
	// Resolve the endpoint path
	path, err := c.resolveEndpoint(endpointKey, urlParams)
	if err != nil {
		return nil, err
	}

	var url string
	if strings.HasPrefix(path, "/") {
		// For root-level endpoints (like telemetry), strip the /api suffix if present
		baseURLRoot := strings.TrimSuffix(strings.TrimRight(c.BaseURL, "/"), "/api")
		url = fmt.Sprintf("%s%s", baseURLRoot, path)
	} else {
		base := strings.TrimRight(c.BaseURL, "/")
		url = fmt.Sprintf("%s/%s", base, path)
	}

	// Add query parameters if any
	if len(queryParams) > 0 {
		var q []string
		for k, v := range queryParams {
			if v != "" {
				q = append(q, fmt.Sprintf("%s=%s", k, v))
			}
		}
		if len(q) > 0 {
			url = fmt.Sprintf("%s?%s", url, strings.Join(q, "&"))
		}
	}

	// Marshal request body once — keep jsonData around for potential retry
	var jsonData []byte
	if data != nil {
		jsonData, err = json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
	}

	httpMethod := strings.ToUpper(method)

	// Build and send the request
	resp, err := c.doRequest(httpMethod, url, jsonData)
	if err != nil {
		return nil, err
	}

	// Auto-refresh on 401 for authenticated endpoints.
	// Public endpoints (auth.login, auth.refresh, telemetry.sync) are excluded
	// to prevent infinite refresh loops since auth.refresh is itself public.
	if resp.StatusCode == 401 && !publicEndpoints[endpointKey] && c.refreshFn != nil {
		resp.Body.Close()

		// Thread-safe token refresh execution
		c.refreshMu.Lock()
		newToken, refreshErr := c.refreshFn()
		c.refreshMu.Unlock()

		if refreshErr != nil {
			// Refresh failed — re-issue the original request so the caller
			// gets a proper 401 response body to inspect.
			return c.doRequest(httpMethod, url, jsonData)
		}

		// Retry with the freshly minted token
		return c.doRequestWithToken(httpMethod, url, jsonData, newToken)
	}

	return resp, nil
}

// doRequest builds and sends an HTTP request, attaching the current token.
func (c *Client) doRequest(method, url string, jsonData []byte) (*http.Response, error) {
	var body io.Reader
	if jsonData != nil {
		body = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if c.getToken != nil {
		token := c.getToken()
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}

	return c.HTTPClient.Do(req)
}

// doRequestWithToken builds and sends an HTTP request with a specific token.
func (c *Client) doRequestWithToken(method, url string, jsonData []byte, token string) (*http.Response, error) {
	var body io.Reader
	if jsonData != nil {
		body = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	return c.HTTPClient.Do(req)
}

// DecodeError attempt to parse a JSON error message from the response body.
// It returns a formatted error including the status code and any message from the API.
func (c *Client) DecodeError(resp *http.Response) error {
	var errResp struct {
		Message string `json:"message"`
		Error   string `json:"error"`
		Detail  string `json:"detail"`
	}

	// Read and buffer the body so we can try to decode it
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("API request failed with status %d (failed to read body: %v)", resp.StatusCode, err)
	}

	var baseErr error
	if err := json.Unmarshal(bodyBytes, &errResp); err == nil {
		for _, msg := range []string{errResp.Message, errResp.Error, errResp.Detail} {
			if msg != "" {
				baseErr = fmt.Errorf("API error: %s (status %d)", msg, resp.StatusCode)
				break
			}
		}
	}

	if baseErr == nil {
		bodySnippet := string(bodyBytes)
		if bodySnippet != "" {
			baseErr = fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, bodySnippet)
		} else {
			baseErr = fmt.Errorf("API request failed with status %d (empty body)", resp.StatusCode)
		}
	}

	switch resp.StatusCode {
	case 401:
		isLoginOrSignup := false
		if resp.Request != nil && resp.Request.URL != nil {
			path := resp.Request.URL.Path
			isLoginOrSignup = strings.Contains(path, "/auth/login/") || strings.Contains(path, "/auth/register/")
		}
		if isLoginOrSignup {
			return errors.New(errors.ErrInvalidCredentials, baseErr.Error(), baseErr)
		}
		return errors.New(errors.ErrUnauthorized, fmt.Sprintf("%v. Your session may have expired. Please run 'agentsecrets login' to authenticate again.", baseErr), baseErr)
	case 403:
		return errors.New(errors.ErrForbidden, fmt.Sprintf("%v. Permission denied.", baseErr), baseErr)
	case 500:
		return errors.New(errors.ErrServerInternal, fmt.Sprintf("%v. Internal server error.", baseErr), baseErr)
	}

	return baseErr
}

// resolveEndpoint converts "category.action" + params into a URL path
func (c *Client) resolveEndpoint(key string, params map[string]string) (string, error) {
	parts := strings.SplitN(key, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid endpoint key %q: must be 'category.action'", key)
	}

	category, action := parts[0], parts[1]
	path, ok := endpointMap[category][action]
	if !ok {
		return "", fmt.Errorf("unknown endpoint: %s.%s", category, action)
	}

	// Replace URL parameters like {project_id} with actual values
	for k, v := range params {
		path = strings.ReplaceAll(path, "{"+k+"}", v)
	}

	return path, nil
}
