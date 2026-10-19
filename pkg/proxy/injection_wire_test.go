package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestInjectionTargetsSurviveTheWire is the regression lock for issue #9.
//
// Injection targets used to ride in the header NAME, which Go canonicalises on
// both sides of the wire: "channel" arrived as "Channel" and a hyphen arrived
// as a dot. The round trip here goes through a real HTTP request, so it fails
// if any future change puts the target back into a header name.
func TestInjectionTargetsSurviveTheWire(t *testing.T) {
	sent := []Injection{
		{Style: "query", Target: "channel", SecretKey: "SLACK_CHANNEL_ID"},
		{Style: "body", Target: "channel", SecretKey: "SLACK_CHANNEL_ID"},
		{Style: "body", Target: "auth.token", SecretKey: "TOKEN"},
		{Style: "body", Target: "x-request-id", SecretKey: "REQUEST_ID"},
		{Style: "body", Target: "user_id", SecretKey: "USER_ID"},
		{Style: "form", Target: "api_key", SecretKey: "API_KEY"},
		{Style: "header", Target: "X-Custom-Name", SecretKey: "CUSTOM"},
		{Style: "bearer", SecretKey: "BEARER_KEY"},
		{Style: "basic", SecretKey: "BASIC_KEY"},
	}

	// Encode on the client, then decode on the server from what actually
	// crossed the wire.
	var got []Injection
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		got, err = parseInjections(r.Header)
		if err != nil {
			t.Errorf("parseInjections: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	applyInjections(req.Header, sent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	resp.Body.Close()

	if len(got) != len(sent) {
		t.Fatalf("round trip returned %d injections, want %d: %+v", len(got), len(sent), got)
	}
	// parseInjections walks a header map, so order is not meaningful. Compare
	// as a multiset and fail on any target that was rewritten.
	remaining := make([]Injection, len(got))
	copy(remaining, got)
	for _, want := range sent {
		found := -1
		for i, g := range remaining {
			if g == want {
				found = i
				break
			}
		}
		if found < 0 {
			t.Fatalf("injection %+v did not survive the wire; got %+v", want, got)
		}
		remaining = append(remaining[:found], remaining[found+1:]...)
	}
}

// TestParseInjectionsAcceptsLegacyTargetHeaders proves older clients and the
// published curl recipes still work: the target stays in the header name, with
// the legacy dot-from-dash rule preserved.
func TestParseInjectionsAcceptsLegacyTargetHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-AS-Inject-Query-channel", "SLACK_CHANNEL_ID")
	h.Set("X-AS-Inject-Body-auth-token", "TOKEN")
	h.Set("X-AS-Inject-Form-api-key", "API_KEY")
	h.Set("X-AS-Inject-Header-X-Custom", "CUSTOM")
	h.Set("X-AS-Inject-Bearer", "BEARER_KEY")

	got, err := parseInjections(h)
	if err != nil {
		t.Fatalf("parseInjections: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d injections, want 5: %+v", len(got), got)
	}

	want := map[string]string{
		"query":  "Channel", // legacy form is mangled by canonicalisation and stays that way
		"body":   "Auth.Token",
		"form":   "Api-Key", // Go canonicalises each dash-separated word
		"header": "X-Custom",
	}
	for _, inj := range got {
		if inj.Style == "bearer" {
			if inj.SecretKey != "BEARER_KEY" {
				t.Errorf("bearer key = %q", inj.SecretKey)
			}
			continue
		}
		if inj.Target != want[inj.Style] {
			t.Errorf("style %s target = %q, want %q", inj.Style, inj.Target, want[inj.Style])
		}
	}
}

// TestParseInjectionsRejectsMalformedTargetedValue keeps a client bug loud
// instead of letting an injection silently vanish.
func TestParseInjectionsRejectsMalformedTargetedValue(t *testing.T) {
	h := http.Header{}
	h.Set("X-AS-Inject-Query", "channel")

	if _, err := parseInjections(h); err == nil {
		t.Fatal("expected an error for a value without target=SECRET_KEY")
	}
}

// TestParseInjectionsSupportsRepeatedTargets covers the repeatable form.
func TestParseInjectionsSupportsRepeatedTargets(t *testing.T) {
	h := http.Header{}
	h.Add("X-AS-Inject-Body", "channel=CHANNEL_ID")
	h.Add("X-AS-Inject-Body", "text=MESSAGE")

	got, err := parseInjections(h)
	if err != nil {
		t.Fatalf("parseInjections: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d injections, want 2: %+v", len(got), got)
	}
	if got[0].Target != "channel" || got[1].Target != "text" {
		t.Errorf("targets = %q, %q", got[0].Target, got[1].Target)
	}
}

// TestParseInjectionsAcceptsSpaceSeparator covers the syntax the published
// docs used ("X-AS-Inject-Query: key GOOGLE_MAPS_KEY"), so a script written
// against those pages keeps working.
func TestParseInjectionsAcceptsSpaceSeparator(t *testing.T) {
	h := http.Header{}
	h.Set("X-AS-Inject-Query", "key GOOGLE_MAPS_KEY")
	h.Set("X-AS-Inject-Header", "x-api-key ANTHROPIC_KEY")

	got, err := parseInjections(h)
	if err != nil {
		t.Fatalf("parseInjections: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d injections, want 2: %+v", len(got), got)
	}
	byStyle := map[string]Injection{}
	for _, inj := range got {
		byStyle[inj.Style] = inj
	}
	if byStyle["query"].Target != "key" || byStyle["query"].SecretKey != "GOOGLE_MAPS_KEY" {
		t.Errorf("query = %+v", byStyle["query"])
	}
	if byStyle["header"].Target != "x-api-key" || byStyle["header"].SecretKey != "ANTHROPIC_KEY" {
		t.Errorf("header = %+v", byStyle["header"])
	}
}
