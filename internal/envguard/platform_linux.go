//go:build linux

package envguard

import "runtime"

func libraryName() string { return "guard_linux_" + runtime.GOARCH + ".so" }
func preloadKey() string  { return "LD_PRELOAD" }
