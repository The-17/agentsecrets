//go:build linux

package keychainauth

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyDaemonPeerAcceptsInstalledBinary(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		t.Fatal(err)
	}
	want, err := computeHash(self)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	if err := verifyDaemonPeer(client, self, want); err != nil {
		t.Fatalf("peer verification failed: %v", err)
	}
	if err := verifyDaemonPeer(client, self, "sha256:0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("a wrong expected hash must fail")
	}
	if err := verifyDaemonPeer(client, filepath.Join(t.TempDir(), "missing"), want); err == nil {
		t.Fatal("a missing expected path must fail")
	}
}
