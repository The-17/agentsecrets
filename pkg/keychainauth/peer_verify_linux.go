//go:build linux

package keychainauth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func verifyDaemonPeer(conn net.Conn, expectedPath, expectedHash string) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("daemon connection is not a Unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get socket fd: %w", err)
	}

	var peer *syscall.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		peer, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return fmt.Errorf("read peer credentials: %w", err)
	}
	if sockErr != nil {
		return fmt.Errorf("read peer credentials: %w", sockErr)
	}
	if peer == nil || peer.Pid <= 0 {
		return fmt.Errorf("daemon socket returned no peer PID")
	}

	procExe := fmt.Sprintf("/proc/%d/exe", peer.Pid)
	peerPath, err := os.Readlink(procExe)
	if err != nil {
		return fmt.Errorf("resolve daemon executable: %w", err)
	}
	peerPath = strings.TrimSuffix(peerPath, " (deleted)")

	expected, err := filepath.EvalSymlinks(expectedPath)
	if err != nil {
		return fmt.Errorf("resolve expected daemon path: %w", err)
	}
	if filepath.Clean(peerPath) != filepath.Clean(expected) {
		return fmt.Errorf("daemon peer is %s, expected %s", peerPath, expected)
	}

	file, err := os.Open(procExe)
	if err != nil {
		return fmt.Errorf("read daemon executable: %w", err)
	}
	defer file.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return fmt.Errorf("hash daemon executable: %w", err)
	}
	got := "sha256:" + hex.EncodeToString(sum.Sum(nil))
	if !strings.EqualFold(got, expectedHash) {
		return fmt.Errorf("daemon binary hash %s does not match installed hash %s", got, expectedHash)
	}
	return nil
}
