package mcp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/The-17/agentsecrets/pkg/proxy"
)

func TestParseInjections(t *testing.T) {
	tests := []struct {
		name    string
		input   map[string]interface{}
		want    []proxy.Injection
		wantErr bool
	}{
		{
			name:  "bearer",
			input: map[string]interface{}{"bearer": "STRIPE_KEY"},
			want:  []proxy.Injection{{Style: "bearer", SecretKey: "STRIPE_KEY"}},
		},
		{
			name:  "basic",
			input: map[string]interface{}{"basic": "DB_CREDS"},
			want:  []proxy.Injection{{Style: "basic", SecretKey: "DB_CREDS"}},
		},
		{
			name:  "header with target",
			input: map[string]interface{}{"header:X-API-Key": "API_KEY"},
			want:  []proxy.Injection{{Style: "header", Target: "X-API-Key", SecretKey: "API_KEY"}},
		},
		{
			name:  "query with target",
			input: map[string]interface{}{"query:api_key": "GMAP_KEY"},
			want:  []proxy.Injection{{Style: "query", Target: "api_key", SecretKey: "GMAP_KEY"}},
		},
		{
			name:  "body with nested path",
			input: map[string]interface{}{"body:auth.token": "TOKEN"},
			want:  []proxy.Injection{{Style: "body", Target: "auth.token", SecretKey: "TOKEN"}},
		},
		{
			name:  "form with target",
			input: map[string]interface{}{"form:password": "PWD"},
			want:  []proxy.Injection{{Style: "form", Target: "password", SecretKey: "PWD"}},
		},
		{
			name:    "header missing target",
			input:   map[string]interface{}{"header": "KEY"},
			wantErr: true,
		},
		{
			name:    "unknown style",
			input:   map[string]interface{}{"oauth": "KEY"},
			wantErr: true,
		},
		{
			name:    "non-string value",
			input:   map[string]interface{}{"bearer": 123},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseInjections(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseInjections() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d injections, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i].Style != tt.want[i].Style {
					t.Errorf("injection[%d].Style = %q, want %q", i, got[i].Style, tt.want[i].Style)
				}
				if got[i].Target != tt.want[i].Target {
					t.Errorf("injection[%d].Target = %q, want %q", i, got[i].Target, tt.want[i].Target)
				}
				if got[i].SecretKey != tt.want[i].SecretKey {
					t.Errorf("injection[%d].SecretKey = %q, want %q", i, got[i].SecretKey, tt.want[i].SecretKey)
				}
			}
		})
	}
}

func TestParseInjectionsMultiple(t *testing.T) {
	input := map[string]interface{}{
		"bearer":          "STRIPE_KEY",
		"header:X-Org-ID": "ORG_ID",
	}

	got, err := parseInjections(input)
	if err != nil {
		t.Fatalf("parseInjections() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d injections, want 2", len(got))
	}

	// Check both injections are present (map order not guaranteed)
	styles := map[string]bool{}
	for _, inj := range got {
		styles[inj.Style] = true
	}
	if !styles["bearer"] || !styles["header"] {
		t.Errorf("expected bearer and header styles, got: %v", styles)
	}
}

func TestParseInjectionsJSON(t *testing.T) {
	jsonStr := `{"bearer": "STRIPE_KEY", "query:api_key": "GMAP_KEY"}`

	got, err := ParseInjectionsJSON(jsonStr)
	if err != nil {
		t.Fatalf("ParseInjectionsJSON() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d injections, want 2", len(got))
	}
}

func TestNewServerCreation(t *testing.T) {
	s := NewServer("dev")
	if s == nil {
		t.Fatal("NewServer() returned nil")
	}
}

// TestRedactValue verifies a freshly minted value is not left in a returned body.
func TestRedactValue(t *testing.T) {
	body := []byte(`{"id":"x","key":"sk_live_secret","label":"key"}`)
	if out := redactValue(body, "sk_live_secret"); strings.Contains(string(out), "sk_live_secret") {
		t.Fatalf("value still present after redaction: %s", out)
	} else if !strings.Contains(string(out), proxy.RedactionPlaceholder) {
		t.Fatalf("placeholder missing after redaction: %s", out)
	}

	if out := redactValue(body, ""); !bytes.Equal(out, body) {
		t.Fatal("empty value must be a no-op")
	}

	if out := redactValue([]byte(`{"a":"v1v2","b":"vv1v2z"}`), "v1v2"); strings.Contains(string(out), "v1v2") {
		t.Fatalf("echoed value survived: %s", out)
	}
}
