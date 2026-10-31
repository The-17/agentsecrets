package commands

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeDocID(t *testing.T) {
	cases := map[string]string{
		"proxy/overview":                "proxy/overview",
		"docs/proxy/overview":           "proxy/overview",
		"https://docs.agentsecrets.tech/docs/proxy/overview": "proxy/overview",
		"https://docs.agentsecrets.tech/docs/concepts/proxy-model#transient-proxy-architecture": "concepts/proxy-model::transient-proxy-architecture",
		"concepts/proxy-model::transient-proxy-architecture":                                    "concepts/proxy-model::transient-proxy-architecture",
	}
	for in, want := range cases {
		if got := normalizeDocID(in); got != want {
			t.Errorf("normalizeDocID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSlugify(t *testing.T) {
	if got := slugify("What is AgentSecrets?"); got != "what-is-agentsecrets" {
		t.Errorf("slugify = %q, want what-is-agentsecrets", got)
	}
}

func TestSearchDocsJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/search" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("q") != "proxy" {
			http.Error(w, "bad q", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Accept") != "application/json" {
			http.Error(w, "missing accept", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"query":"proxy","results":[{"id":"proxy/overview","url":"https://x/docs/proxy/overview","title":"T","group":"G","label":"L","snippet":"S","score":1.5}]}`)
	}))
	defer srv.Close()

	resp, err := searchDocs(srv.URL, "proxy", false)
	if err != nil {
		t.Fatalf("searchDocs: %v", err)
	}
	if len(resp.Results) != 1 || resp.Results[0].ID != "proxy/overview" {
		t.Fatalf("unexpected results: %+v", resp.Results)
	}
}

func TestSearchDocsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := searchDocs(srv.URL, "x", false); err == nil {
		t.Fatal("expected an error on HTTP 500")
	}
}

func TestFetchDocContentRaw(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/docs" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("id") != "proxy/overview" {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "# Credential Proxy Overview\n\nBody.")
	}))
	defer srv.Close()

	// A full URL must normalize to the bare id the API expects.
	got, err := fetchDocContent(srv.URL, "https://docs.agentsecrets.tech/docs/proxy/overview")
	if err != nil {
		t.Fatalf("fetchDocContent: %v", err)
	}
	if !strings.Contains(got, "Credential Proxy Overview") {
		t.Errorf("content = %q", got)
	}
}

func TestFetchDocContentNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Both /api/docs and the /llms-full.txt fallback 404.
		http.NotFound(w, r)
	}))
	defer srv.Close()

	if _, err := fetchDocContent(srv.URL, "does/not/exist"); err == nil {
		t.Fatal("expected a not-found error")
	}
}

func TestFetchDocIndexParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/llms.txt" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, "# AgentSecrets\n\n## Documentation Map\n\n"+
			"- [What is AgentSecrets?](https://docs.agentsecrets.tech/docs/)\n"+
			"- [Credential Proxy Overview](https://docs.agentsecrets.tech/docs/proxy/overview)\n")
	}))
	defer srv.Close()

	entries, err := fetchDocIndex(srv.URL)
	if err != nil {
		t.Fatalf("fetchDocIndex: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if entries[0].ID != "what-is-agentsecrets" {
		t.Errorf("root id = %q, want what-is-agentsecrets", entries[0].ID)
	}
	if entries[1].ID != "proxy/overview" {
		t.Errorf("id = %q, want proxy/overview", entries[1].ID)
	}
}

func TestDocEntryJSONShape(t *testing.T) {
	b, err := json.Marshal([]docEntry{{ID: "a", Title: "A", URL: "u"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"id":"a"`) {
		t.Fatalf("json = %s", b)
	}
}
