package sidecar

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	// The sidecar's OPAQUE operations are comparatively expensive and are the
	// only thing an unauthenticated caller can ask it to do before the bearer
	// token is checked. Pacing is a coarse CPU guard, not a fairness scheduler.
	// Each process owns its own table, so serverless instances scale the ceiling
	// horizontally rather than sharing one global quota.
	rateLimitBurst   = 120
	rateLimitWindow  = time.Second
	rateLimitMaxKeys = 1024
)

type bucket struct {
	tokens int
	last   time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	burst   int
	window  time.Duration
	maxKeys int
	now     func() time.Time
}

func newRateLimiter(burst int, window time.Duration, maxKeys int, now func() time.Time) *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*bucket),
		burst:   burst,
		window:  window,
		maxKeys: maxKeys,
		now:     now,
	}
}

func defaultRateLimiter() *rateLimiter {
	return newRateLimiter(rateLimitBurst, rateLimitWindow, rateLimitMaxKeys, time.Now)
}

// clientKey uses only the connection's remote host. X-Forwarded-For and
// similar headers are client-controlled data, not an identity: trusting them
// lets a caller mint an unlimited number of buckets. The port is stripped so
// successive connections from one host share a bucket. A malformed or absent
// RemoteAddr collapses to one shared bucket rather than producing a fresh key
// per request, which would disable the limit entirely.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "unknown"
	}
	return host
}

func (l *rateLimiter) allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if b, ok := l.buckets[key]; ok {
		if now.Sub(b.last) >= l.window {
			b.tokens = l.burst
			b.last = now
		}
		if b.tokens <= 0 {
			return false
		}
		b.tokens--
		return true
	}

	// Bound the table. When it is full, drop idle buckets; if it is still
	// full, refuse new keys instead of growing without limit or silently
	// disabling the limit. Both outcomes are loud (429), never a bypass.
	if len(l.buckets) >= l.maxKeys {
		l.prune(now)
	}
	if len(l.buckets) >= l.maxKeys {
		return false
	}
	l.buckets[key] = &bucket{tokens: l.burst - 1, last: now}
	return true
}

// prune removes buckets that have been idle for a full window. Such a bucket
// would be fully refilled on its next use anyway, so dropping it changes no
// observable behaviour beyond freeing memory.
func (l *rateLimiter) prune(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.last) >= l.window {
			delete(l.buckets, k)
		}
	}
}

// pace runs before authentication so a flood without a valid bearer token is
// throttled too. /healthz is deliberately not paced.
func (l *rateLimiter) pace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientKey(r)) {
			writeErr(w, http.StatusTooManyRequests, errors.New("rate limited"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
