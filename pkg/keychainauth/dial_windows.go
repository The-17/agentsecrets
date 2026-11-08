//go:build windows

package keychainauth

import (
	"errors"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32       = syscall.NewLazyDLL("kernel32.dll")
	procPeekNamedPipe = modkernel32.NewProc("PeekNamedPipe")
	procWaitNamedPipe = modkernel32.NewProc("WaitNamedPipeW")
)

const (
	// pipeBusyTimeout bounds the wait for a free named-pipe instance. The daemon
	// creates its next listening instance only after accepting the previous
	// client, so a second connection can land in the gap where none is pending.
	// Two seconds covers that gap without turning a dead daemon into a hang.
	pipeBusyTimeout = 2 * time.Second
	pipeWaitSlice   = 250 * time.Millisecond
)

func peekNamedPipe(handle windows.Handle, lpTotalBytesAvail *uint32) error {
	r1, _, err := procPeekNamedPipe.Call(
		uintptr(handle),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(lpTotalBytesAvail)),
		0,
	)
	if r1 == 0 {
		return err
	}
	return nil
}

func waitNamedPipe(name *uint16, timeoutMS uint32) error {
	r1, _, err := procWaitNamedPipe.Call(uintptr(unsafe.Pointer(name)), uintptr(timeoutMS))
	if r1 != 0 {
		return nil
	}
	return err
}

// isPipeBusy reports whether a dial failed because the daemon has no free pipe
// instance. ERROR_PIPE_BUSY means the daemon IS listening; reporting it as
// "daemon is not running" made doctor (slow probes) and env (two probes back to
// back) disagree about the same daemon.
func isPipeBusy(err error) bool {
	return errors.Is(err, windows.ERROR_PIPE_BUSY)
}

// dialCLOEXEC connects to the Windows Named Pipe, waiting for a free instance.
// A single CreateFile can return ERROR_PIPE_BUSY even against a healthy daemon:
// keychain-auth keeps one pending pipe instance at a time and creates the next
// one only after the previous client has been accepted. WaitNamedPipe is the
// documented client-side response; without it a second dial in the same process
// loses the race and is misreported as a dead daemon.
func dialCLOEXEC(sockPath string) (net.Conn, error) {
	name, err := windows.UTF16PtrFromString(sockPath)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(pipeBusyTimeout)
	for {
		h, dialErr := windows.CreateFile(
			name,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,
			nil,
			windows.OPEN_EXISTING,
			0,
			0,
		)
		if dialErr == nil {
			return &PipeConn{handle: h}, nil
		}
		if !isPipeBusy(dialErr) || !time.Now().Before(deadline) {
			return nil, dialErr
		}

		waitMS := uint32(pipeWaitSlice / time.Millisecond)
		if remaining := time.Until(deadline); remaining < pipeWaitSlice {
			waitMS = uint32(remaining / time.Millisecond)
			if waitMS == 0 {
				waitMS = 1
			}
		}
		if waitErr := waitNamedPipe(name, waitMS); waitErr != nil {
			// ERROR_SEM_TIMEOUT is the expected "still busy" answer; retry the
			// CreateFile. Any other wait error (notably ERROR_FILE_NOT_FOUND)
			// means the pipe itself is gone, so surface that instead.
			if errors.Is(waitErr, windows.ERROR_SEM_TIMEOUT) {
				continue
			}
			return nil, waitErr
		}
	}
}

// PipeConn implements net.Conn for a Windows Named Pipe.
type PipeConn struct {
	handle       windows.Handle
	readDeadline time.Time
}

type pipeError struct {
	error
	timeout bool
}

func (e *pipeError) Timeout() bool   { return e.timeout }
func (e *pipeError) Temporary() bool { return e.timeout }

func (c *PipeConn) Read(b []byte) (int, error) {
	if !c.readDeadline.IsZero() {
		// Poll for data until the deadline
		for {
			var avail uint32
			err := peekNamedPipe(c.handle, &avail)
			if err != nil {
				return 0, err
			}
			if avail > 0 {
				break // data is ready to be read
			}
			if time.Now().After(c.readDeadline) {
				return 0, &pipeError{error: os.ErrDeadlineExceeded, timeout: true}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	var done uint32
	err := windows.ReadFile(c.handle, b, &done, nil)
	if err != nil {
		if err == windows.ERROR_BROKEN_PIPE {
			return 0, os.ErrClosed
		}
		return 0, err
	}
	return int(done), nil
}

func (c *PipeConn) Write(b []byte) (int, error) {
	var done uint32
	err := windows.WriteFile(c.handle, b, &done, nil)
	if err != nil {
		return 0, err
	}
	return int(done), nil
}

func (c *PipeConn) Close() error {
	return windows.CloseHandle(c.handle)
}

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

func (c *PipeConn) LocalAddr() net.Addr  { return pipeAddr("keychain-auth-pipe") }
func (c *PipeConn) RemoteAddr() net.Addr { return pipeAddr("keychain-auth-pipe") }

func (c *PipeConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *PipeConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *PipeConn) SetWriteDeadline(t time.Time) error {
	return nil
}
