package secrets

import (
	"strings"
	"testing"
)

func TestNormalizeValue(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"plain", "sk-abc123", "sk-abc123", false},
		{"trailing newline", "sk-abc123\n", "sk-abc123", false},
		{"trailing crlf", "sk-abc123\r\n", "sk-abc123", false},
		{"empty", "", "", true},
		{"only newline", "\n", "", true},
		{"preserves inner whitespace", "  padded  ", "  padded  ", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeValue([]byte(tc.in))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFingerprintIsStableAndShort(t *testing.T) {
	a := Fingerprint("sk-abc123")
	b := Fingerprint("sk-abc123")
	if a != b {
		t.Fatalf("fingerprint not stable: %q != %q", a, b)
	}
	if len(a) != 12 {
		t.Fatalf("fingerprint length = %d, want 12", len(a))
	}
	if a == Fingerprint("sk-abc124") {
		t.Fatal("distinct values produced the same fingerprint")
	}
	if strings.Contains(a, "sk-abc123") {
		t.Fatal("fingerprint leaked the value")
	}
}

func TestRunSourceCommand(t *testing.T) {
	got, err := ReadValueFromCommand("printf 'from-command\\n'", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "from-command" {
		t.Fatalf("got %q, want %q", got, "from-command")
	}
}

func TestRunSourceCommandExtract(t *testing.T) {
	got, err := ReadValueFromCommand(`printf '{"data":{"key":"sk_minted"}}'`, "data.key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "sk_minted" {
		t.Fatalf("got %q, want %q", got, "sk_minted")
	}
}

func TestRunSourceCommandEmptyOutput(t *testing.T) {
	if _, err := ReadValueFromCommand("printf ''", ""); err == nil {
		t.Fatal("expected error for empty command output")
	}
}

func TestRunSourceCommandFailure(t *testing.T) {
	if _, err := ReadValueFromCommand("exit 3", ""); err == nil {
		t.Fatal("expected error for failing command")
	}
}

func TestSetFromReaderRejectsEmpty(t *testing.T) {
	s := &Service{}
	if _, err := s.SetFromReader("MY_KEY", strings.NewReader(""), ""); err == nil {
		t.Fatal("expected error for empty value")
	}
}

func TestSetFromReaderRejectsOversize(t *testing.T) {
	s := &Service{}
	big := strings.Repeat("a", MaxProvisionInput+1)
	if _, err := s.SetFromReader("MY_KEY", strings.NewReader(big), ""); err == nil {
		t.Fatal("expected error for oversize value")
	}
}

func TestSetFromReaderRejectsEmptyKey(t *testing.T) {
	s := &Service{}
	if _, err := s.SetFromReader("  ", strings.NewReader("v"), ""); err == nil {
		t.Fatal("expected error for empty key name")
	}
}

func TestExtractJSONPath(t *testing.T) {
	body := []byte(`{"account":{"id":"acct_1","data":{"key":"sk_live_abc123","nested":{"deep":"tok"}}},"items":[{"name":"a"},{"name":"b"}]}`)

	cases := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{"nested string", "account.data.key", "sk_live_abc123", false},
		{"deep key", "account.data.nested.deep", "tok", false},
		{"array index", "items.1.name", "b", false},
		{"missing key", "account.data.other", "", true},
		{"non-string leaf", "account.id.len", "", true},
	}

	// top-level object key
	if got, err := ExtractJSONPath(body, "account.id"); err != nil || got != "acct_1" {
		t.Fatalf("account.id = %q, %v (want acct_1, nil)", got, err)
	}
	for _, tc := range cases[1:] {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExtractJSONPath(body, tc.path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}

	if _, err := ExtractJSONPath([]byte("not json{"), "a"); err == nil {
		t.Fatal("expected error for non-JSON body")
	}
	if _, err := ExtractJSONPath([]byte(`{"a":null}`), "a"); err == nil {
		t.Fatal("expected error for null leaf")
	}
	if _, err := ExtractJSONPath([]byte(`{"a":""}`), "a"); err == nil {
		t.Fatal("expected error for empty-string leaf")
	}
}
