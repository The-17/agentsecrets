package keychainauth

import (
	"fmt"
	"net"
)

// verifyDaemonPeerAtDial resolves the daemon binary we intend to use and asks
// the platform verifier to confirm the connected peer is that binary. It runs
// before any request is sent, so a planted socket cannot receive a secret.
func verifyDaemonPeerAtDial(conn net.Conn) error {
	path := findBestDaemon()
	if path == "" {
		return fmt.Errorf("cannot locate the installed keychain-auth binary")
	}
	want, err := computeHash(path)
	if err != nil {
		return fmt.Errorf("hash installed daemon binary: %w", err)
	}
	if err := verifyDaemonPeer(conn, path, want); err != nil {
		return err
	}
	return nil
}
