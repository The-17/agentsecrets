package keychainauth

import (
	"os"
	"path/filepath"
	"runtime"
)

var socketPathOverride string

// SetSocketPathOverride overrides the socket path for unit testing.
func SetSocketPathOverride(path string) {
	socketPathOverride = path
}

// UserSocketPath returns the user-writable socket path on the current OS.
// This is used for user-mode daemon fallback (startDirect) when root system sockets are not writable.
func UserSocketPath() string {
	if socketPathOverride != "" {
		return socketPathOverride
	}
	if runtime.GOOS == "windows" {
		return `\\.\pipe\keychain-auth`
	}
	if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "keychain-auth", "agent.sock")
	}

	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir != "" {
		if info, err := os.Stat(runtimeDir); err != nil || !info.IsDir() {
			runtimeDir = ""
		}
	}

	if runtimeDir == "" {
		home, _ := os.UserHomeDir()
		runtimeDir = filepath.Join(home, ".cache")
	}
	return filepath.Join(runtimeDir, "keychain-auth", "agent.sock")
}

// RemoveStaleSockets deletes daemon socket files that no longer have a live
// listener. This is an explicit repair action, called only from the recovery
// ladder, so a read-only availability probe never removes shared state.
func RemoveStaleSockets() {
	if runtime.GOOS == "windows" {
		return
	}
	for _, path := range []string{"/run/keychain-auth/agent.sock", UserSocketPath(), socketPathOverride} {
		if path == "" {
			continue
		}
		if c, err := dialCLOEXEC(path); err == nil {
			_ = c.Close()
			continue // a live daemon owns this socket
		}
		_ = os.Remove(path)
	}
}

// SocketPath returns the active keychain-auth Unix socket path or named pipe path on Windows.
// It checks whether a system socket is actively dialable before falling back to user paths.
func SocketPath() string {
	if socketPathOverride != "" {
		return socketPathOverride
	}
	if runtime.GOOS == "windows" {
		return `\\.\pipe\keychain-auth`
	}
	if runtime.GOOS == "darwin" {
		return UserSocketPath()
	}

	// Linux / WSL: If system socket exists AND is dialable, prefer system socket.
	systemSock := "/run/keychain-auth/agent.sock"
	if _, err := os.Stat("/run/keychain-auth"); err == nil {
		if c, err := dialCLOEXEC(systemSock); err == nil {
			c.Close()
			return systemSock
		}
	}

	// Check if user socket is actively dialable
	userSock := UserSocketPath()
	if c, err := dialCLOEXEC(userSock); err == nil {
		c.Close()
		return userSock
	}

	// Default fallback: if /run/keychain-auth directory exists, return system socket path;
	// otherwise return user socket path.
	if _, err := os.Stat("/run/keychain-auth"); err == nil {
		return systemSock
	}
	return userSock
}
