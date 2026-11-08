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

	useTestResolver(t, hop1.URL)
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

	useTestResolver(t, resolver.URL)
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

	useTestResolver(t, resolver.URL)
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

	useTestResolver(t, resolver.URL)
	t.Setenv(envToken, "workload-token")

	if _, err := Call(CallRequest{TargetURL: "https://api.example.com/x", Method: "GET"}, Selection{Mode: ModeCloud}); err == nil {
		t.Fatal("expected an error for a type-confused status_code")
	}
}

// A resolver outage must fail closed. If cloud mode ever fell back to local
// resolution when the resolver was unreachable, an attacker who can block the
// resolver (or just wait for an outage) would get requests served from the
// keychain, bypassing the resolver's scope and allowlist enforcement.
func TestAdversarialCloudOutageNeverFallsBackToLocal(t *testing.T) {
	isolateEnv(t)

	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	// Cloud env delivery now uses the resolver (ResolverURL), not the control
	// plane, so the outage simulation must point the resolver at a dead host.
	useTestResolver(t, deadURL)
	t.Setenv(envToken, "workload-token")

	localUsed := false
	got, err := SecretsForEnv(Selection{Mode: ModeCloud}, func() (map[string]string, error) {
		localUsed = true
		return map[string]string{"STRIPE_KEY": "sk_local"}, nil
	}, "")
	if err == nil {
		t.Fatalf("expected an error when the control plane is unreachable, got %v", got)
	}
	if localUsed {
		t.Fatal("cloud mode fell back to local resolution during an outage: a downgrade bypasses the resolver trust boundary")
	}
	if len(got) != 0 {
		t.Fatalf("cloud outage returned secrets (%v); it must return nothing", got)
	}
}

// The same for the call path: an unreachable resolver is an error, never a
// result, and never a redirect into another transport.
func TestAdversarialResolverUnreachableFailsClosed(t *testing.T) {
	isolateEnv(t)

	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	useTestResolver(t, deadURL)
	t.Setenv(envToken, "workload-token")

	res, err := Call(CallRequest{TargetURL: "https://api.example.com/x", Method: "GET"}, Selection{Mode: ModeCloud})
	if err == nil {
		t.Fatalf("expected an error when the resolver is unreachable, got %+v", res)
	}
	if res != nil {
		t.Fatalf("unreachable resolver returned a result: %+v", res)
	}
}

func TestAdversarialResolverHugeBodyIsBounded(t *testing.T) {
	isolateEnv(t)
	huge := strings.Repeat("A", 13<<20) // 13 MiB, over the 12 MiB cap
	payload, _ := json.Marshal(map[string]any{"status_code": 200, "body": huge})
	resolver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer resolver.Close()

	useTestResolver(t, resolver.URL)
	t.Setenv(envToken, "workload-token")

	if _, err := Call(CallRequest{TargetURL: "https://api.example.com/x", Method: "GET"}, Selection{Mode: ModeCloud}); err == nil {
		t.Fatal("an oversized resolver body must be rejected, not buffered without bound")
	}
}
