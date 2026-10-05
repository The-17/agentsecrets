//go:build windows

package envguard

import "os"

type fileIdentity struct{ uid int }

// fileOwner has no uid notion to check on Windows; ownership enforcement
// there is handled by the child DACL path, not the loader.
func fileOwner(fi os.FileInfo) (fileIdentity, bool) {
	return fileIdentity{}, false
}
