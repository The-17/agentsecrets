package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestFetchWorkloadEnvDoesNotFollowRedirect pins the same client-side SSRF as
// the gateway path: a compromised or hostile control plane can answer the
// workload-env POST with a 3xx to an internal or metadata endpoint, and a
// default http.Client follows it. The response is data, not an instruction to
// fetch another host.
func TestFetchWorkloadEnvDoesNotFollowRedirect(t *testing.T) {
	var hits int32
	exfil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"secrets":{"LEAK":"x"}}}`))
	}))
	defer exfil.Close()

	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, exfil.URL+"/latest/meta-data/", http.StatusFound)
	}))
	defer cp.Close()

	_, err := FetchWorkloadEnv(context.Background(), cp.URL+"/api", "token", "")
	if err == nil {
		t.Fatal("expected an error when the control plane answers with a redirect")
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("client followed the control-plane redirect and hit the target %d time(s): SSRF", n)
	}
}
