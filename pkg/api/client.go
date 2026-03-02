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
	"strings"
	"time"
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
		"list":   "secrets/{project_id}/",
		"create": "secrets/",
		"get":    "secrets/{project_id}/{key}/",
		"update": "secrets/{project_id}/{key}/",
		"delete": "secrets/{project_id}/{key}/",
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
		"remove_member":    "workspaces/{workspace_id}/members/{email}/",
		"role_update":      "workspaces/{workspace_id}/members/{user_id}/role/",
		"allowlist_list":   "workspaces/{workspace_id}/allowlist/",
		"allowlist_add":    "workspaces/{workspace_id}/allowlist/",
		"allowlist_remove": "workspaces/{workspace_id}/allowlist/{domain}/",
		"allowlist_log":    "workspaces/{workspace_id}/allowlist/log/",
	},
	"users": {
		"public_key": "users/{email}/public-key/",
	},
}

// publicEndpoints are endpoints that don't require an auth token
var publicEndpoints = map[string]bool{
	"auth.signup":  true,
	"auth.login":   true,
	"auth.refresh": true,
}

// Client handles all HTTP communication with the AgentSecrets API server.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	// getToken is a function that returns the current access token.
	// This is injected so the API client doesn't depend on the config package directly.
	getToken func() string
}

// NewClient creates a new API client with the default base URL.
func NewClient(tokenFunc func() string) *Client {
	return &Client{
		BaseURL:    DefaultBaseURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		getToken:   tokenFunc,
	}
}

// Call makes an API request to the specified endpoint.
//
// endpointKey uses dot notation like "auth.login" or "secrets.get".
// method is the HTTP method (GET, POST, PUT, DELETE).
// data is the request body (will be JSON-encoded), can be nil.
// urlParams are substituted into the endpoint path template.
//
// Example:
//
//	resp, err := client.Call("secrets.get", "GET", nil, map[string]string{
//	    "project_id": "uuid-here",
//	    "key":        "DATABASE_URL",
//	})
func (c *Client) Call(endpointKey, method string, data interface{}, urlParams map[string]string) (*http.Response, error) {
	// Resolve the endpoint path
	path, err := c.resolveEndpoint(endpointKey, urlParams)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/%s", c.BaseURL, path)

	// Build request body
	var body io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		body = bytes.NewBuffer(jsonData)
	}

	// Create HTTP request
	req, err := http.NewRequest(strings.ToUpper(method), url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add auth header if not a public endpoint
	if !publicEndpoints[endpointKey] && c.getToken != nil {
		token := c.getToken()
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}

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

	if err := json.Unmarshal(bodyBytes, &errResp); err == nil {
		for _, msg := range []string{errResp.Message, errResp.Error, errResp.Detail} {
			if msg != "" {
				return fmt.Errorf("API error: %s (status %d)", msg, resp.StatusCode)
			}
		}
	}

	bodySnippet := string(bodyBytes)
	if len(bodySnippet) > 100 {
		bodySnippet = bodySnippet[:100] + "..."
	}

	if bodySnippet != "" {
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, bodySnippet)
	}

	return fmt.Errorf("API request failed with status %d (empty body)", resp.StatusCode)
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
