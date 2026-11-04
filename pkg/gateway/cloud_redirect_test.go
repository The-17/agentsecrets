package gateway

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestCallCloudDoesNotFollowResolverRedirect pins a client-side SSRF.
//
// callCloud used a default http.Client, which follows 3xx responses. A
// compromised or hostile resolver can answer with a redirect to an internal or
// metadata endpoint (169.254.169.254, 127.0.0.1, ...) and the CLI follows it.
// The resolver's response is data to decode, never an instruction to fetch
// another location. A redirect must be refused, not chased.
func TestCallCloudDoesNotFollowResolverRedirect(t *testing.T) {
	isolateEnv(t)

	var exfilHits int32
	exfil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&exfilHits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("secret-metadata"))
	}))
	defer exfil.Close()

	resolver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An attacker-controlled resolver pointing the client at an internal host.
		http.Redirect(w, r, exfil.URL+"/latest/meta-data/", http.StatusFound)
	}))
	defer resolver.Close()

	t.Setenv(envResolver, resolver.URL)
	t.Setenv(envToken, "workload-token")

	_, err := Call(
		CallRequest{TargetURL: "https://api.example.com/x", Method: "GET"},
		Selection{Mode: ModeCloud},
	)
	if err == nil {
		t.Fatal("expected an error when the resolver answers with a redirect")
	}
	if n := atomic.LoadInt32(&exfilHits); n != 0 {
		t.Fatalf("client followed the resolver redirect and hit the redirect target %d time(s): client-side SSRF", n)
	}
}

// TestCallCloudRejectsUnreadableResponse proves a hostile resolver cannot make
// the client treat garbage as a credential response. It must fail closed, never
// silently return an empty success or fall back to another transport.
func TestCallCloudRejectsUnreadableResponse(t *testing.T) {
	isolateEnv(t)

	resolver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not-json-at-all`))
	}))
	defer resolver.Close()

	t.Setenv(envResolver, resolver.URL)
	t.Setenv(envToken, "workload-token")

	res, err := Call(
		CallRequest{TargetURL: "https://api.example.com/x", Method: "GET"},
		Selection{Mode: ModeCloud},
	)
	if err == nil {
		t.Fatalf("expected an error for an unreadable resolver response, got %+v", res)
	}
	if res != nil {
		t.Fatalf("a failed decode must not return a result: %+v", res)
	}
}
