package commands

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/The-17/agentsecrets/pkg/proxy"
)

// TestBuildCallJSONSuccess mirrors the success path.
func TestBuildCallJSONSuccess(t *testing.T) {
	result := &proxy.CallResult{
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"ok": true}`),
	}
	out := buildCallJSON(result, 42)
	if out.Status != 200 {
		t.Errorf("Status = %d, want 200", out.Status)
	}
	if out.Body != `{"ok": true}` {
		t.Errorf("Body = %q, want %q", out.Body, `{"ok": true}`)
	}
	if out.Redacted {
		t.Error("Redacted = true, want false")
	}
	if out.DurationMs != 42 {
		t.Errorf("DurationMs = %d, want 42", out.DurationMs)
	}
	if out.Error != "" {
		t.Error("Error should be empty on success")
	}
	if got, ok := out.Headers["Content-Type"]; !ok || len(got) == 0 || got[0] != "application/json" {
		t.Errorf("Headers[Content-Type] = %v, want [application/json]", out.Headers)
	}
}

// TestBuildCallJSONError400 mirrors the >=400 error path.
// Note: the function prefers Message over Error when both are present.
func TestBuildCallJSONError400(t *testing.T) {
	result := &proxy.CallResult{
		StatusCode: 404,
		Headers:    map[string][]string{},
		Body:       []byte(`{"error":"not_found","message":"not found"}`),
	}
	out := buildCallJSON(result, 0)
	if out.Status != 404 {
		t.Errorf("Status = %d, want 404", out.Status)
	}
	if out.Error != "not found" {
		t.Errorf("Error = %q, want %q", out.Error, "not found")
	}
	if out.DurationMs != 0 {
		t.Errorf("DurationMs = %d, want 0", out.DurationMs)
	}
	if got, ok := out.Headers["Content-Type"]; ok && len(got) > 0 {
		t.Error("Headers should be empty")
	}
}

// TestEmitCallJSONSuccess encodes and prints to stdout.
func TestEmitCallJSONSuccess(t *testing.T) {
	// Capture stdout
	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	out := callResultJSON{
		Status:     200,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       `{"ok": true}`,
		Redacted:   false,
		DurationMs: 10,
	}

	err := emitCallJSON(out)
	// Restore stdout
	w.Close()
	os.Stdout = stdout

	if err != nil {
		t.Fatalf("emitCallJSON error: %v", err)
	}

	// Read what was written
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	var parsed callResultJSON
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}
	if parsed.Status != 200 {
		t.Errorf("parsed.Status = %d, want 200", parsed.Status)
	}
	if parsed.Body != `{"ok": true}` {
		t.Errorf("parsed.Body = %q, want %q", parsed.Body, `{"ok": true}`)
	}
	if parsed.Redacted {
		t.Error("parsed.Redacted = true, want false")
	}
	if parsed.DurationMs != 10 {
		t.Errorf("parsed.DurationMs = %d, want 10", parsed.DurationMs)
	}
	if got, ok := parsed.Headers["Content-Type"]; !ok || len(got) == 0 || got[0] != "application/json" {
		t.Errorf("parsed.Headers[Content-Type] = %v, want [application/json]", parsed.Headers)
	}
}

// TestEmitCallJSONError returns silent exit on >=400.
func TestEmitCallJSONError(t *testing.T) {
	out := callResultJSON{
		Status:     502,
		Headers:    map[string][]string{},
		Body:       "Bad Gateway",
		Redacted:   false,
		DurationMs: 0,
		Error:      "upstream",
	}
	err := emitCallJSON(out)
	if err == nil {
		t.Error("emitCallJSON expected error")
		return
	}
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		if exitErr.Code != 1 {
			t.Errorf("exitErr.Code = %d, want 1", exitErr.Code)
		}
		if !exitErr.Silent {
			t.Error("exitErr.Silent = false, want true")
		}
	} else {
		t.Errorf("err = %v, want *ExitError", err)
	}
}

// TestEmitCallJSONErrorZeroStatus returns silent exit on error string.
func TestEmitCallJSONErrorZeroStatus(t *testing.T) {
	out := callResultJSON{
		Status:     0,
		Headers:    map[string][]string{},
		Body:       "",
		Redacted:   false,
		DurationMs: 0,
		Error:      "something went wrong",
	}
	err := emitCallJSON(out)
	if err == nil {
		t.Error("emitCallJSON expected error")
		return
	}
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		if exitErr.Code != 1 {
			t.Errorf("exitErr.Code = %d, want 1", exitErr.Code)
		}
		if !exitErr.Silent {
			t.Error("exitErr.Silent = false, want true")
		}
	} else {
		t.Errorf("err = %v, want *ExitError", err)
	}
}
