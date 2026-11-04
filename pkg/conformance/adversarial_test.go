//go:build adversarial

package conformance

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
)

// TestAdversarialControlPlaneGarbageBody pins client invariant C2: a 2xx that
// is not valid JSON must be rejected, never passed through to a caller or
// decoded as an envelope. A hostile or buggy control plane returning garbage
// must fail closed. CallJSON is where the envelope is unwrapped, so that is the
// layer asserted here.
func TestAdversarialControlPlaneGarbageBody(t *testing.T) {
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json at all"))
	}))
	defer cp.Close()

	client := api.NewClientWithURL(cp.URL+"/api", func() string { return "user-jwt" })
	_, err := api.CallJSON[map[string]any](client, "projects.list", http.MethodGet, nil, nil, nil)
	if err == nil {
		t.Fatal("expected an error for a non-JSON 200 body from the control plane")
	}
}
