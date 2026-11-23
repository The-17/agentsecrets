package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSessionRotationRollback(t *testing.T) {
	s := &Server{}
	s.SetSessionToken("agt_old")
	original := s.GetSessionToken()

	newToken, err := s.rotateSessionToken()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if newToken == original {
		t.Fatal("rotation must produce a new token")
	}

	req := httptest.NewRequest(http.MethodPost, "/rollback-session", nil)
	req.Header.Set("X-AS-Session-Token", newToken)
	rec := httptest.NewRecorder()
	s.handleRollbackSession(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("rollback status %d: %s", rec.Code, rec.Body.String())
	}
	if got := s.GetSessionToken(); got != original {
		t.Errorf("token after rollback = %q, want %q", got, original)
	}
}

func TestSessionRotationRollbackOnlyOnce(t *testing.T) {
	s := &Server{}
	s.SetSessionToken("agt_old")
	newToken, err := s.rotateSessionToken()
	if err != nil {
		t.Fatal(err)
	}

	call := func(token string) int {
		req := httptest.NewRequest(http.MethodPost, "/rollback-session", nil)
		req.Header.Set("X-AS-Session-Token", token)
		rec := httptest.NewRecorder()
		s.handleRollbackSession(rec, req)
		return rec.Code
	}

	if code := call(newToken); code != http.StatusOK {
		t.Fatalf("first rollback status %d", code)
	}
	if code := call(originalTokenAfterRollback(s)); code != http.StatusConflict {
		t.Fatalf("second rollback should be refused, got %d", code)
	}
}

func originalTokenAfterRollback(s *Server) string { return s.GetSessionToken() }
