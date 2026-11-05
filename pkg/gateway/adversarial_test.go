//go:build adversarial

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// These fixtures drive the cloud resolver path against a hostile resolver that
// does more than the already-fixed single redirect: multi-hop redirect chains,
// malformed 3xx, incomplete envelopes (contract C4), type-confused fields, and
// oversized bodies. Each is expected to fail closed.

func TestAdversarialResolverRedirectChainNotFollowed(t *testing.T) {
	isolateEnv(t)

	var exfilHits int32
	exfil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&exfilHits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("metadata"))
	}))
	defer exfil.Close()

	var hop2 *httptest.Server
	hop1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, hop2.URL+"/second", http.StatusFound)
	}))
	defer hop1.Close()
	hop2 = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, exfil.URL+"/latest/meta-data/", http.StatusFound)
	}))
	defer hop2.Close()

	t.Setenv(envResolver, hop1.URL)
	t.Setenv(envToken, "workload-token")

	if _, err := Call(CallRequest{TargetURL: "https://api.example.com/x", Method: "GET"}, Selection{Mode: ModeCloud}); err == nil {
		t.Fatal("expected an error for a multi-hop redirect chain")
	}
	if n := atomic.LoadInt32(&exfilHits); n != 0 {
		t.Fatalf("client followed a redirect chain to the exfil host %d time(s): client-side SSRF", n)
	}
}

func TestAdversarialResolverRedirectWithoutLocation(t *testing.T) {
	isolateEnv(t)
	resolver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusFound) // no Location header
	}))
	defer resolver.Close()

	t.Setenv(envResolver, resolver.URL)
	t.Setenv(envToken, "workload-token")

	if _, err := Call(CallRequest{TargetURL: "https://api.example.com/x", Method: "GET"}, Selection{Mode: ModeCloud}); err == nil {
		t.Fatal("expected an error for a 3xx with no Location header")
	}
}

func TestAdversarialResolverMissingStatusCodeRejected(t *testing.T) {
	isolateEnv(t)
	resolver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"body":"ok","headers":{"X":"y"}}`)) // no status_code
	}))
	defer resolver.Close()

	t.Setenv(envResolver, resolver.URL)
	t.Setenv(envToken, "workload-token")

	res, err := Call(CallRequest{TargetURL: "https://api.example.com/x", Method: "GET"}, Selection{Mode: ModeCloud})
	if err == nil {
		t.Fatalf("a resolver envelope with no status_code must be rejected (contract C4), got success: %+v", res)
	}
}

func TestAdversarialResolverTypeConfusedStatusCodeRejected(t *testing.T) {
	isolateEnv(t)
	resolver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status_code":"200","body":"ok"}`)) // string, not int
	}))
	defer resolver.Close()

	t.Setenv(envResolver, resolver.URL)
	t.Setenv(envToken, "workload-token")

	if _, err := Call(CallRequest{TargetURL: "https://api.example.com/x", Method: "GET"}, Selection{Mode: ModeCloud}); err == nil {
		t.Fatal("expected an error for a type-confused status_code")
	}
}

func TestAdversarialResolverHugeBodyIsBounded(t *testing.T) {
	isolateEnv(t)
	huge := strings.Repeat("A", 9<<20) // 9 MiB, over the 8 MiB cap
	payload, _ := json.Marshal(map[string]any{"status_code": 200, "body": huge})
	resolver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer resolver.Close()

	t.Setenv(envResolver, resolver.URL)
	t.Setenv(envToken, "workload-token")

	if _, err := Call(CallRequest{TargetURL: "https://api.example.com/x", Method: "GET"}, Selection{Mode: ModeCloud}); err == nil {
		t.Fatal("an oversized resolver body must be rejected, not buffered without bound")
	}
}
