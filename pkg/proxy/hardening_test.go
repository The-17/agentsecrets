package proxy

import (
	"net"
	"net/http"
	"testing"
	"time"
)

// TestSSRFCoverageBlocksNonRoutableDestinations pins the gaps that let a
// hostname resolve to a wildcard, broadcast, or multicast address.
func TestSSRFCoverageBlocksNonRoutableDestinations(t *testing.T) {
	blocked := []string{
		"0.0.0.0", "0.1.2.3", "255.255.255.255",
		"224.0.0.1", "239.255.255.250", "ff02::1",
		"::", "127.0.0.1", "169.254.169.254", "10.1.2.3",
		"172.16.0.1", "192.168.1.1", "100.64.0.1", "fc00::1",
	}
	for _, addr := range blocked {
		t.Run(addr, func(t *testing.T) {
			ip := net.ParseIP(addr)
			if ip == nil {
				t.Fatalf("bad test address %q", addr)
			}
			if !isPrivateOrLoopbackIP(ip) {
				t.Errorf("%s was not blocked", addr)
			}
		})
	}

	allowed := []string{"1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"}
	for _, addr := range allowed {
		t.Run("allow_"+addr, func(t *testing.T) {
			ip := net.ParseIP(addr)
			if ip == nil {
				t.Fatalf("bad test address %q", addr)
			}
			if isPrivateOrLoopbackIP(ip) {
				t.Errorf("public address %s was blocked", addr)
			}
		})
	}
}

func TestProxyHTTPServerHasReadLimits(t *testing.T) {
	srv := newProxyHTTPServer(http.NewServeMux())
	if srv.ReadHeaderTimeout <= 0 {
		t.Error("ReadHeaderTimeout is unset; a slow header stream can hold the listener")
	}
	if srv.ReadTimeout <= 0 {
		t.Error("ReadTimeout is unset; a slow body stream can hold a connection")
	}
	if srv.IdleTimeout <= 0 {
		t.Error("IdleTimeout is unset; idle connections are never reclaimed")
	}
	if srv.ReadTimeout < 2*time.Minute {
		t.Errorf("ReadTimeout %v is too short for a proxied request", srv.ReadTimeout)
	}
}
