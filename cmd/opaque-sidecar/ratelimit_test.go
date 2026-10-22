package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterBlocksAfterBurst(t *testing.T) {
	limiter := newRateLimiter(3, time.Minute)
	handler := limiter.middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	allowed := 0
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/login/start", nil)
		req.RemoteAddr = "203.0.113.9:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			allowed++
		} else if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("unexpected status %d", rec.Code)
		}
	}
	if allowed != 3 {
		t.Fatalf("burst of 3 allowed %d requests", allowed)
	}

	// A different client must not be punished for the first one.
	other := httptest.NewRequest(http.MethodPost, "/v1/login/start", nil)
	other.RemoteAddr = "198.51.100.4:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, other)
	if rec.Code != http.StatusOK {
		t.Fatalf("unrelated client got %d", rec.Code)
	}
}
