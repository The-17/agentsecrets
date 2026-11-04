package api

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestClientDoesNotFollowRedirect covers the shared control-plane transport,
// not just the workload-env path: every management call carries the user JWT,
// so a 3xx from the API must not be followed to another host (client-side
// SSRF). Both constructors must build the refusing transport.
func TestClientDoesNotFollowRedirect(t *testing.T) {
	constructors := map[string]func(baseURL string, token func() string) *Client{
		"NewClient": func(baseURL string, token func() string) *Client {
			old := ResolveBaseURLFunc
			ResolveBaseURLFunc = func() string { return baseURL }
			t.Cleanup(func() { ResolveBaseURLFunc = old })
			return NewClient(token)
		},
		"NewClientWithURL": NewClientWithURL,
	}

	for name, build := range constructors {
		t.Run(name, func(t *testing.T) {
			var hits int32
			exfil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&hits, 1)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":{"secrets":[]}}`))
			}))
			defer exfil.Close()

			cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, exfil.URL+"/latest/meta-data/", http.StatusFound)
			}))
			defer cp.Close()

			client := build(cp.URL+"/api", func() string { return "user-jwt" })
			resp, err := client.Call("projects.list", http.MethodGet, nil, nil, nil)
			if err == nil {
				resp.Body.Close()
				t.Fatal("expected an error when the control plane answers with a redirect")
			}
			if n := atomic.LoadInt32(&hits); n != 0 {
				t.Fatalf("client followed the control-plane redirect and hit the target %d time(s): SSRF", n)
			}
		})
	}
}
