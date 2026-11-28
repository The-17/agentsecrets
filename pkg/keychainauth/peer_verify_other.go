//go:build !linux

package keychainauth

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// verifyDaemonPeer is best effort off Linux. Linux can read the peer PID and
// executable from the kernel and the socket, which closes F5 outright. macOS
// and Windows do not expose the peer executable to an unprivileged client in
// the same way, so the strongest available check is to ask the daemon binary
// we installed to report its own identity and compare hashes. A fake daemon
// can still imitate that answer; this limitation is documented rather than
// hidden.
func verifyDaemonPeer(conn net.Conn, expectedPath, expectedHash string) error {
	output, err := exec.Command(expectedPath, "identity", "--json").CombinedOutput()
	if err != nil {
		return fmt.Errorf("query daemon identity: %w", err)
	}
	start := strings.IndexByte(string(output), '{')
	if start < 0 {
		return fmt.Errorf("daemon identity returned no JSON")
	}
	var identity struct {
		BinaryHash string `json:"binary_hash"`
	}
	if err := json.Unmarshal(output[start:], &identity); err != nil {
		return fmt.Errorf("parse daemon identity: %w", err)
	}
	if !strings.EqualFold(identity.BinaryHash, expectedHash) {
		return fmt.Errorf("daemon identity hash %s does not match installed hash %s", identity.BinaryHash, expectedHash)
	}
	return nil
}
