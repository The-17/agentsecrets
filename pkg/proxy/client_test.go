package proxy

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestPIDFileRoundtrip(t *testing.T) {
	testPort := 9999
	if err := WritePIDFile(testPort); err != nil {
		t.Fatalf("WritePIDFile failed: %v", err)
	}
	defer RemovePIDFile()

	pid, _, port, err := ReadPIDFile()
	if err != nil {
		t.Fatalf("ReadPIDFile failed: %v", err)
	}

	if pid != os.Getpid() {
		t.Errorf("expected PID %d, got %d", os.Getpid(), pid)
	}
	if port != testPort {
		t.Errorf("expected port %d, got %d", testPort, port)
	}
}

func TestIsProcessAliveSelf(t *testing.T) {
	if !IsProcessAlive(os.Getpid()) {
		t.Errorf("expected current process %d to be alive", os.Getpid())
	}
}

func TestIsProcessAliveNonExistent(t *testing.T) {
	// 999999 is typically a non-existent PID
	if IsProcessAlive(999999) {
		t.Errorf("expected PID 999999 to be dead")
	}
}

func TestIsProxyRunningWithMockServer(t *testing.T) {
	// Start an HTTP test server that responds on /health
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on loopback: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	ts := &httptest.Server{
		Listener: listener,
		Config:   &http.Server{Handler: mux},
	}
	ts.Start()
	defer ts.Close()

	if err := WritePIDFile(port); err != nil {
		t.Fatalf("WritePIDFile failed: %v", err)
	}
	defer RemovePIDFile()

	pid, gotPort, running := IsProxyRunning()
	if !running {
		t.Errorf("expected proxy to be recognized as running")
	}
	if pid != os.Getpid() {
		t.Errorf("expected PID %d, got %d", os.Getpid(), pid)
	}
	if gotPort != port {
		t.Errorf("expected port %d, got %d", port, gotPort)
	}
}

func TestIsProxyRunningNonDestructiveOnFailure(t *testing.T) {
	// Write a PID file with a port that is NOT listening
	fakePort := 54321
	if err := WritePIDFile(fakePort); err != nil {
		t.Fatalf("WritePIDFile failed: %v", err)
	}
	defer RemovePIDFile()

	_, _, running := IsProxyRunning()
	if running {
		t.Errorf("expected proxy to NOT be running on port %d", fakePort)
	}

	// Crucial invariant: IsProxyRunning must NOT delete the PID file on probe failure!
	path, _ := PIDFilePath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("PID file was deleted by IsProxyRunning; read-only checks must never delete state")
	}
}
