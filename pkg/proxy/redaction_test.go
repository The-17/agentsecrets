package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Redaction is an output mutation: the engine rewrites what the upstream sent.
// A missed secret leaks a credential; an over-eager match corrupts a valid
// answer and the caller never learns why. These tests pin both directions.

// A bare prefix of a short secret must not rewrite ordinary content that
// happens to share those bytes. This is the false positive that used to fire:
// a 22-char secret redacted its first 14 characters, so an unrelated metric
// name sharing the prefix came back as "[REDACTED_BY_AGENTSECRETS]e_metrics".
func TestRedactSecretFromResponseLeavesSharedPrefixAlone(t *testing.T) {
	secretValue := "recall_homepage_status" // 22 chars
	if len(secretValue) != 22 {
		t.Fatalf("fixture length drifted: got %d, want 22", len(secretValue))
	}
	body := []byte(`{"metric":"recall_homepage_metrics","value":0.97}`)

	got := string(redactSecretFromResponse(body, secretValue))

	if got != string(body) {
		t.Fatalf("ordinary body was mutated:\n got: %s\nwant: %s", got, string(body))
	}
}

// A bare prefix echo of a 22-char secret is no longer treated as a leak by the
// prefix rule. Masked forms (rule 4) and the full value (rule 1) still are.
// This records the tradeoff the thresholds encode rather than leaving it to be
// rediscovered as a "leak".
func TestRedactSecretFromResponseBareShortPrefixIsNotTreatedAsLeak(t *testing.T) {
	secretValue := "recall_homepage_status"
	echo := secretValue[:14] // what an API would truncate to

	got := string(redactSecretFromResponse([]byte("Invalid key: "+echo), secretValue))

	if got != "Invalid key: "+echo {
		t.Fatalf("short bare prefix was redacted, want it left alone: %q", got)
	}
}

// Real credentials are 24+ chars and keep two-thirds prefix coverage. The
// fixture deliberately has no live-key prefix: a live-key shaped string of
// this length is a Stripe key to GitHub push protection even though it is a
// test constant, and a blocked push helps nobody.
func TestRedactSecretFromResponseRedactsLongCredentialPrefix(t *testing.T) {
	secretValue := "fixture_credential_ABCDEFGHIJKLM" // 32 chars, synthetic
	if len(secretValue) < 24 {
		t.Fatalf("fixture length drifted: got %d, want >= 24", len(secretValue))
	}
	echo := secretValue[:len(secretValue)*2/3]

	got := string(redactSecretFromResponse([]byte("Invalid key: "+echo), secretValue))

	if strings.Contains(got, echo) {
		t.Fatalf("SECURITY: two-thirds prefix of a 32-char credential survived: %q", got)
	}
	if !strings.Contains(got, RedactionPlaceholder) {
		t.Fatalf("want the placeholder in %q", got)
	}
}

// Tightening the prefix rule must not drop masked-echo coverage, which is the
// form APIs actually print in error messages.
func TestRedactSecretFromResponseStillCatchesMaskedEcho(t *testing.T) {
	secretValue := "recall_homepage_status"
	body := []byte(`{"error":"Invalid key: recall_h***xyz"}`)

	got := string(redactSecretFromResponse(body, secretValue))

	if strings.Contains(got, "recall_h***xyz") {
		t.Fatalf("SECURITY: masked echo survived: %q", got)
	}
	if !strings.Contains(got, RedactionPlaceholder) {
		t.Fatalf("want the placeholder in %q", got)
	}
}

// End-to-end through Execute. Redaction only runs when the body contains the
// exact value (engine.go redactResponse), so the body carries a real echo of
// the secret plus an unrelated field that shares its prefix. The echo must go;
// the unrelated field must survive intact. Under the old thresholds the second
// replacement also rewrote the metric name.
func TestEngineExecuteKeepsBodySharingSecretPrefix(t *testing.T) {
	secretValue := "recall_homepage_status"
	upstreamBody := `{"echoed":"` + secretValue + `","metric":"recall_homepage_metrics","value":0.97}`

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, upstreamBody)
	}))
	defer upstream.Close()

	engine := &Engine{
		ProjectID:        "test-project",
		ResolveAllowlist: mockAllowlist(),
		Client:           upstream.Client(),
		ResolveSecret:    mockResolver(map[string]string{"METRICS_KEY": secretValue}),
	}

	result, err := engine.Execute(CallRequest{
		TargetURL:  upstream.URL + "/data",
		Method:     "GET",
		Injections: []Injection{{Style: "bearer", SecretKey: "METRICS_KEY"}},
	})
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	got := string(result.Body)
	if strings.Contains(got, secretValue) {
		t.Fatalf("SECURITY: echoed secret survived: %q", got)
	}
	if !strings.Contains(got, `"metric":"recall_homepage_metrics"`) {
		t.Fatalf("unrelated field sharing the secret prefix was mutated: %q", got)
	}
}
