//go:build !linux && !darwin

package envguard

// No preload mechanism is wired up for this platform yet, so the guard is not
// applied and the child runs as before. Windows support lands in a later phase.
func libraryName() string { return "" }
func preloadKey() string  { return "" }
