//go:build adversarial

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Hostile control-plane fixtures for the workload env path. The single redirect
// case is already covered; these probe chains, oversized bodies, and a 2xx that
// is not the documented envelope.

func TestAdversarialWorkloadEnvRedirectChainNotFollowed(t *testing.T) {
	var exfilHits int32
	exfil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&exfilHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer exfil.Close()

	var hop2 *httptest.Server
	hop1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, hop2.URL+"/api/workloads/env/", http.StatusFound)
	}))
	defer hop1.Close()
	hop2 = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, exfil.URL+"/api/workloads/env/", http.StatusFound)
	}))
	defer hop2.Close()

	if _, err := FetchWorkloadEnv(context.Background(), hop1.URL, "tok", ""); err == nil {
		t.Fatal("expected an error for a multi-hop redirect chain")
	}
	if n := atomic.LoadInt32(&exfilHits); n != 0 {
		t.Fatalf("client followed a redirect chain to the exfil host %d time(s)", n)
	}
}

func TestAdversarialWorkloadEnvHugeBodyIsBounded(t *testing.T) {
	huge := strings.Repeat("A", 9<<20)
	payload, _ := json.Marshal(map[string]any{"data": map[string]any{"secrets": map[string]string{"PAD": huge}}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	if _, err := FetchWorkloadEnv(context.Background(), srv.URL, "tok", ""); err == nil {
		t.Fatal("an oversized workload-env body must be rejected, not buffered without bound")
	}
}

func TestAdversarialWorkloadEnvNonEnvelopeRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"secrets":{"STRIPE_KEY":"sk_live_leak"}}`)) // not the {"data":...} envelope
	}))
	defer srv.Close()

	res, err := FetchWorkloadEnv(context.Background(), srv.URL, "tok", "")
	if err == nil {
		t.Fatalf("a 2xx that is not the documented envelope must be rejected, got %v", res)
	}
}
