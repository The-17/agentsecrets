package log

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
)

// TestQueryRemote_SendsFilterAsQueryParams is a regression test for the bug where
// QueryRemote passed its filter map in the urlParams slot (path-template
// substitution) instead of the queryParams slot. Because the "log.list" endpoint
// path ("audit/logs/") contains no {placeholders}, every filter — including the
// required workspace_id — was silently dropped, so the server answered
// 422 "workspace_id is required" (surfaced as "Invalid Entry") for every remote
// audit-log query (MCP logs_list / logs_summary and the CLI remote path).
func TestQueryRemote_SendsFilterAsQueryParams(t *testing.T) {
	var gotPath, gotRawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotRawQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data": []}`))
	}))
	defer srv.Close()

	client := api.NewClientWithURL(srv.URL, func() string { return "test-token" })
	svc := &Service{client: client}

	if _, err := svc.QueryRemote("ws-123", Filter{ProjectID: "proj-9", Limit: 1000}); err != nil {
		t.Fatalf("QueryRemote returned error: %v", err)
	}

	if gotPath != "/audit/logs/" {
		t.Fatalf("path = %q, want %q", gotPath, "/audit/logs/")
	}
	for _, want := range []string{"workspace_id=ws-123", "project_id=proj-9", "limit=1000"} {
		if !strings.Contains(gotRawQuery, want) {
			t.Fatalf("raw query %q missing %q — filter params are being dropped "+
				"(urlParams/queryParams slot swap)", gotRawQuery, want)
		}
	}
}
