package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIClient(t *testing.T) {
	// 1. Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers
		if !strings.Contains(r.URL.Path, "login") && r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"message": "invalid token"})
			return
		}

		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Handle specific endpoints
		switch r.URL.Path {
		case "/workspaces/":
			if r.Method == "POST" {
				var body map[string]interface{}
				json.NewDecoder(r.Body).Decode(&body)
				if name, ok := body["name"].(string); ok && name != "" {
					w.WriteHeader(http.StatusCreated)
					json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]string{"id": "ws-1"}})
				} else {
					w.WriteHeader(http.StatusBadRequest)
				}
			}
		case "/auth/login/":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// 2. Client setup with lazy token provider
	tokenProvider := func() string {
		return "test-token"
	}
	client := NewClient(tokenProvider)
	client.BaseURL = server.URL // Override for test

	// 3. Test simple POST (login is a public endpoint)
	resp, err := client.Call("auth.login", "POST", map[string]string{"email": "t@t.com"}, nil)
	if err != nil {
		t.Fatalf("Call failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// 4. Test POST with body (requires token)
	data := map[string]string{"name": "New Workspace"}
	resp, err = client.Call("workspaces.create", "POST", data, nil)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", resp.StatusCode)
	}

	var res struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&res)
	if res.Data.ID != "ws-1" {
		t.Errorf("Expected ID ws-1, got %s", res.Data.ID)
	}

	// 5. Test Unauthorized (empty token on non-public endpoint)
	unauthClient := NewClient(func() string { return "" })
	unauthClient.BaseURL = server.URL
	resp, err = unauthClient.Call("workspaces.list", "GET", nil, nil)
	if err != nil {
		t.Fatalf("Unauth call failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}

func TestAPIParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/workspaces/ws-123/members/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"data": []}`)
	}))
	defer server.Close()

	client := NewClient(func() string { return "token" })
	client.BaseURL = server.URL

	// Test URL param insertion
	resp, err := client.Call("workspaces.members", "GET", nil, map[string]string{"workspace_id": "ws-123"})
	if err != nil {
		t.Fatalf("Call with params failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}
