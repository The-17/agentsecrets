package commands

import (
	"testing"
)

// TestParsePlainHeaders covers --set-header, added so a caller can send a
// Content-Type (issue #9) without storing a non-secret as a secret.
func TestParsePlainHeaders(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		want    map[string]string
		wantErr bool
	}{
		{
			name: "content type",
			in:   []string{"Content-Type=application/json"},
			want: map[string]string{"Content-Type": "application/json"},
		},
		{
			name: "value may contain equals",
			in:   []string{"Accept=application/json;q=1"},
			want: map[string]string{"Accept": "application/json;q=1"},
		},
		{
			name: "name is trimmed",
			in:   []string{" X-Trace =abc"},
			want: map[string]string{"X-Trace": "abc"},
		},
		{
			name: "multiple",
			in:   []string{"A=1", "B=2"},
			want: map[string]string{"A": "1", "B": "2"},
		},
		{name: "no equals", in: []string{"Content-Type"}, wantErr: true},
		{name: "empty name", in: []string{"=value"}, wantErr: true},
		{name: "empty value", in: []string{"Header="}, wantErr: true},
		{name: "reserved bearer", in: []string{"X-AS-Inject-Bearer=EVIL"}, wantErr: true},
		{name: "reserved lowercase", in: []string{"x-as-target-url=https://evil"}, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePlainHeaders(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

// TestParsePlainHeadersEmpty keeps the no-flag case a no-op rather than a nil
// map that callers would have to check.
func TestParsePlainHeadersEmpty(t *testing.T) {
	got, err := parsePlainHeaders(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}
