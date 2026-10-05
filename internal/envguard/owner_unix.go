//go:build unix

package envguard

import (
	"os"
	"syscall"
)

type fileIdentity struct{ uid int }

// fileOwner returns the owning uid of fi on Unix. The second return is false
// only when the platform cannot report ownership (then the world-writable
// check in verifiedLibrary still applies).
func fileOwner(fi os.FileInfo) (fileIdentity, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, false
	}
	return fileIdentity{uid: int(st.Uid)}, true
}
