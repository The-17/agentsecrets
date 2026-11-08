//go:build windows

package keychainauth

import (
	"net"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestDialCLOEXEC_WaitsForFreeInstance pins the regression behind
// "[ERR-999] keychain-auth daemon is not running" on Windows. keychain-auth
// creates its next pipe instance only after accepting the previous client, so
// there is a window where every instance is busy. A single CreateFile returns
// ERROR_PIPE_BUSY there even though the daemon is healthy.
//
// This test is deliberately written against dialCLOEXEC alone so it compiles
// and fails on the unfixed tree too: on 3.3.6 it returns ERROR_PIPE_BUSY
// immediately instead of waiting for the next instance.
func TestDialCLOEXEC_WaitsForFreeInstance(t *testing.T) {
	const pipeName = `\\.\pipe\agentsecrets-pipe-busy-regression`

	name, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		t.Fatalf("encode pipe name: %v", err)
	}

	const mode = windows.PIPE_TYPE_BYTE | windows.PIPE_READMODE_BYTE | windows.PIPE_WAIT
	const maxInstances = 2

	h1, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX, mode, maxInstances, 1024, 1024, 0, nil)
	if err != nil {
		t.Fatalf("create first pipe instance: %v", err)
	}
	defer windows.CloseHandle(h1)

	occupant, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatalf("connect occupying client: %v", err)
	}
	defer windows.CloseHandle(occupant)

	type dialResult struct {
		conn net.Conn
		err  error
	}
	done := make(chan dialResult, 1)
	go func() {
		c, dialErr := dialCLOEXEC(pipeName)
		done <- dialResult{conn: c, err: dialErr}
	}()

	// Let the dial land in the busy window, then publish the daemon's next
	// instance. This is exactly the recycling the real daemon does.
	time.Sleep(150 * time.Millisecond)
	h2, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX, mode, maxInstances, 1024, 1024, 0, nil)
	if err != nil {
		t.Fatalf("create second pipe instance: %v", err)
	}
	defer windows.CloseHandle(h2)

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("dial should wait for a free instance, got: %v", r.err)
		}
		defer r.conn.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("dial did not complete within the busy timeout")
	}
}
