//go:build darwin

package envguard

import "runtime"

func libraryName() string { return "guard_darwin_" + runtime.GOARCH + ".dylib" }
func preloadKey() string  { return "DYLD_INSERT_LIBRARIES" }
