package sidecar

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fakeClock(start time.Time) (func() time.Time, func(time.Duration)) {
	now := start
	return func() time.Time { return now }, func(d time.Duration) { now = now.Add(d) }
}

func TestRateLimiterBlocksBurstAndRefills(t *testing.T) {
	now, advance := fakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	l := newRateLimiter(2, time.Second, 10, now)

	for i := 0; i < 2; i++ {
		if !l.allow("10.0.0.1") {
			t.Fatalf("request %d within burst was blocked", i+1)
		}
	}
	if l.allow("10.0.0.1") {
		t.Fatal("third request in the same window was allowed")
	}

	advance(time.Second)
	if !l.allow("10.0.0.1") {
		t.Fatal("window did not refill")
	}
}

func TestRateLimiterSharesBucketAcrossPorts(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	l := newRateLimiter(1, time.Second, 10, now)
	paced := l.pace(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	allowed, blocked := 0, 0
	for _, addr := range []string{"10.0.0.1:1111", "10.0.0.1:2222", "10.0.0.1:3333"} {
		r := httptest.NewRequest(http.MethodPost, "/v1/login/start", nil)
		r.RemoteAddr = addr
		w := httptest.NewRecorder()
		paced.ServeHTTP(w, r)
		if w.Code == http.StatusNoContent {
			allowed++
		} else if w.Code == http.StatusTooManyRequests {
			blocked++
		}
	}

	// All three addresses are one host. With a port-stripping bug each would
	// have opened a fresh bucket and all three would have passed.
	if allowed != 1 || blocked != 2 {
		t.Fatalf("allowed=%d blocked=%d, want 1/2: ports did not share a bucket", allowed, blocked)
	}
	if l.buckets["10.0.0.1"] == nil {
		t.Fatal("no bucket keyed by host: RemoteAddr was not split")
	}
}

func TestRateLimiterIgnoresForwardedFor(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	l := newRateLimiter(2, time.Second, 10, now)
	paced := l.pace(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for i := 0; i < 3; i++ {
		r := httptest.NewRequest(http.MethodPost, "/v1/login/start", nil)
		r.RemoteAddr = "10.0.0.1:1234"
		// A client can set these to anything. If the limiter trusted them,
		// every request below would land in its own bucket and pass.
		r.Header.Set("X-Forwarded-For", "203.0.113."+strings.Repeat("1", i+1))
		r.Header.Set("X-Real-IP", "198.51.100."+strings.Repeat("2", i+1))
		w := httptest.NewRecorder()
		paced.ServeHTTP(w, r)
		if i < 2 && w.Code != http.StatusNoContent {
			t.Fatalf("request %d was blocked unexpectedly: %d", i+1, w.Code)
		}
		if i == 2 && w.Code != http.StatusTooManyRequests {
			t.Fatalf("forwarded headers bypassed the limit: status %d", w.Code)
		}
	}
	if len(l.buckets) != 1 {
		t.Fatalf("forwarded headers created %d buckets, want 1", len(l.buckets))
	}
}

func TestRateLimiterBoundsTableAndFailsClosed(t *testing.T) {
	now, advance := fakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	l := newRateLimiter(5, time.Second, 2, now)

	if !l.allow("10.0.0.1") || !l.allow("10.0.0.2") {
		t.Fatal("first two hosts should be admitted")
	}
	if l.allow("10.0.0.3") {
		t.Fatal("a third host grew the table past its bound")
	}
	if len(l.buckets) != 2 {
		t.Fatalf("table has %d entries, want the bound of 2", len(l.buckets))
	}

	advance(time.Second)
	if !l.allow("10.0.0.3") {
		t.Fatal("idle buckets were not pruned after a window")
	}
}

func TestMuxPacesBeforeAuthAndLeavesHealthzAlone(t *testing.T) {
	t.Setenv("OPAQUE_SIDECAR_TOKEN", "test-token")
	t.Setenv("OPAQUE_SERVER_KEY_MATERIAL", "")
	s, err := New(true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := s.Mux()

	// Unauthenticated requests count toward the bucket: after the burst they
	// are refused with 429 rather than reaching the bearer-token check (401).
	var last int
	for i := 0; i < rateLimitBurst+1; i++ {
		r := httptest.NewRequest(http.MethodPost, "/v1/login/start", nil)
		r.RemoteAddr = "10.0.0.9:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		last = w.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("last unauthenticated request = %d, want 429 (limiter must run before auth)", last)
	}

	// Health checks stay available and are not paced.
	var healthzCodes atomic.Int32
	for i := 0; i < rateLimitBurst+50; i++ {
		r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		r.RemoteAddr = "10.0.0.9:9999"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code == http.StatusOK {
			healthzCodes.Add(1)
		}
	}
	if int(healthzCodes.Load()) != rateLimitBurst+50 {
		t.Fatalf("%d/%d healthz requests returned 200", healthzCodes.Load(), rateLimitBurst+50)
	}
}
