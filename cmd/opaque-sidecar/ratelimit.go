package main

import (
	"net/http"
	"sync"
	"time"
)

// rateLimiter is a coarse per-IP token bucket. It exists because the sidecar
// may sit behind a tunnel where the bearer token is the only access control,
// and an unthrottled endpoint would let an attacker grind that token off.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	burst   int
	refill  time.Duration
}

type bucket struct {
	tokens int
	last   time.Time
}

func newRateLimiter(burst int, window time.Duration) *rateLimiter {
	return &rateLimiter{buckets: make(map[string]*bucket), burst: burst, refill: window}
}

func (l *rateLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	if elapsed := now.Sub(b.last); elapsed >= l.refill {
		// Refill the whole burst once the window has passed. Coarse on purpose:
		// this throttles a tunnel, it is not a fairness scheduler.
		b.tokens = l.burst
		b.last = now
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

func (l *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.RemoteAddr
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			// Behind a tunnel every request arrives from the proxy, so the
			// forwarded address is the only per-client key available.
			host = fwd
		}
		if !l.allow(host) {
			http.Error(w, `{"error":"rate limited"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
