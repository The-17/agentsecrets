package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestEngineRefusesCrossHostRedirect proves an allowlisted host cannot walk an
// injected header to a second host with a 3xx. The allowlist is checked only on
// the original URL, so following Location would defeat it.
func TestEngineRefusesCrossHostRedirect(t *testing.T) {
	var reached int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reached, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Api-Key"); got != "sk_test_redirect" {
			t.Errorf("origin header = %q, want the injected value", got)
		}
		http.Redirect(w, r, target.URL+"/steal", http.StatusFound)
	}))
	defer origin.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		Client:           newEngineHTTPClient(origin.Client().Transport),
		ResolveSecret:    mockResolver(map[string]string{"API_KEY": "sk_test_redirect"}),
		ResolveAllowlist: mockAllowlist("127.0.0.1"),
	}

	result, err := engine.Execute(CallRequest{
		TargetURL: origin.URL + "/v1/start",
		Method:    "GET",
		Injections: []Injection{
			{Style: "header", Target: "X-Api-Key", SecretKey: "API_KEY"},
		},
	})
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if result.StatusCode != http.StatusFound {
		t.Errorf("StatusCode = %d, want the unfollowed 302", result.StatusCode)
	}
	if n := atomic.LoadInt32(&reached); n != 0 {
		t.Errorf("redirect target was reached %d time(s); the client followed the 3xx", n)
	}
}

func TestNewEngineHTTPClientRefusesRedirects(t *testing.T) {
	client := newEngineHTTPClient(http.DefaultTransport)
	if client.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil; the client will follow redirects")
	}
	if err := client.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect() = %v, want http.ErrUseLastResponse", err)
	}
}

// TestInjectAllSetsGetBody covers the replay path. net/http uses GetBody to
// resend a request (for example after a 307/308), so replacing Body without it
// produces a request with a stale ContentLength and an unreadable body.
func TestInjectAllSetsGetBody(t *testing.T) {
	req, err := http.NewRequest("POST", "https://api.example.com/v1", strings.NewReader(`{"amount":1}`))
	if err != nil {
		t.Fatal(err)
	}

	if err := InjectAll(req,
		[]string{"sk_body_value"},
		[]Injection{{Style: "body", Target: "auth.key", SecretKey: "API_KEY"}},
	); err != nil {
		t.Fatalf("InjectAll() error: %v", err)
	}

	if req.GetBody == nil {
		t.Fatal("GetBody is nil after body injection")
	}
	body, err := req.GetBody()
	if err != nil {
		t.Fatalf("GetBody() error: %v", err)
	}
	defer body.Close()
	raw, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"key":"sk_body_value"`) {
		t.Errorf("replayed body = %s, want the injected value", raw)
	}
	if int64(len(raw)) != req.ContentLength {
		t.Errorf("ContentLength = %d, replayed body = %d bytes", req.ContentLength, len(raw))
	}
}

func TestInjectBodySetsGetBody(t *testing.T) {
	req, err := http.NewRequest("POST", "https://api.example.com/v1", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}

	if err := injectBody(req, "sk_single_value", "auth.key"); err != nil {
		t.Fatalf("injectBody() error: %v", err)
	}
	if req.GetBody == nil {
		t.Fatal("GetBody is nil after single body injection")
	}
	body, err := req.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	raw, _ := io.ReadAll(body)
	if !strings.Contains(string(raw), `"key":"sk_single_value"`) {
		t.Errorf("replayed body = %s, want the injected value", raw)
	}
}
