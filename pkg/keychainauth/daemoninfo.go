package keychainauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// probeTimeout bounds every diagnostic subprocess. A wedged or half-started daemon
// binary must never hang the CLI: these probes run on the startup path of ordinary
// commands, so they fail fast and let the caller fall back.
const probeTimeout = 5 * time.Second

// runProbe executes a short-lived diagnostic command under probeTimeout and returns
// its combined output.
func runProbe(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// DaemonInfo is the daemon's own report of how it is configured, obtained from
// `keychain-auth status --json`. It is the authoritative answer to "which mode is
// the daemon in, where is its store, and does registration need sudo" — questions
// this package previously answered by guessing from socket paths.
type DaemonInfo struct {
	Running      bool   `json:"daemon_running"`
	Version      string `json:"version"`
	Mode         string `json:"mode"` // "system" | "user"
	ConfigPath   string `json:"config_path"`
	SocketPath   string `json:"socket_path"`
	RequiresSudo bool   `json:"requires_sudo"`
}

// QueryDaemonInfo asks the keychain-auth binary to describe its own configuration.
// The binary reports the mode it would run in and the store it would use, so this
// works whether or not the daemon is currently up.
func QueryDaemonInfo(keychainAuthPath string) (*DaemonInfo, error) {
	if keychainAuthPath == "" {
		return nil, fmt.Errorf("keychain-auth path is empty")
	}
	out, err := runProbe(keychainAuthPath, "status", "--json")
	if err != nil {
		// Older daemons lack `status --json`; the caller falls back to path probing.
		return nil, fmt.Errorf("query daemon status: %w", err)
	}
	// CombinedOutput may carry warnings on stderr ahead of the JSON body.
	start := bytes.IndexByte(out, '{')
	if start < 0 {
		return nil, fmt.Errorf("daemon status returned no JSON: %s", strings.TrimSpace(string(out)))
	}
	var info DaemonInfo
	if err := json.Unmarshal(out[start:], &info); err != nil {
		return nil, fmt.Errorf("parse daemon status: %w", err)
	}
	return &info, nil
}

// registeredBinary mirrors one entry of keychain-auth's trust store. Only the
// fields needed to reason about our own registration are modelled.
type registeredBinary struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}

// daemonStore mirrors the on-disk keychain-auth config (its trust store). Only the
// fields needed to reason about our own registration are modelled; extra fields in
// the file (e.g. protocol_version) are ignored by encoding/json.
type daemonStore struct {
	RegisteredBinaries []registeredBinary `json:"registered_binaries"`
}

// readDaemonStore loads the daemon's trust store. It is best-effort: the store may
// be unreadable by an unprivileged user, which is not an error — the authoritative
// registration probe is `keychain-auth check` plus a live request.
func readDaemonStore(configPath string) (*daemonStore, error) {
	if configPath == "" {
		return nil, fmt.Errorf("config path is empty")
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var store daemonStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("parse daemon store %s: %w", configPath, err)
	}
	return &store, nil
}

// SelfPath returns the resolved absolute path of the running agentsecrets binary —
// the identity keychain-auth registers and hash-verifies. Symlinks are resolved
// because the daemon compares against the real path it sees on the peer process.
func SelfPath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot determine own binary path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("cannot resolve binary symlinks: %w", err)
	}
	return resolved, nil
}

// registrationState describes whether the daemon's store trusts this exact binary.
type registrationState struct {
	SelfPath     string
	SelfHash     string
	StoreHash    string // hash the store recorded for our path, if any
	PathFound    bool   // our path appears in the store
	HashMatches  bool   // the recorded hash matches our current bytes
	StoreReadErr error  // store unreadable (unprivileged); probe via `check` instead
}

// inspectRegistration compares this binary against the daemon's trust store.
func inspectRegistration(configPath string) (*registrationState, error) {
	selfPath, err := SelfPath()
	if err != nil {
		return nil, err
	}
	selfHash, err := computeHash(selfPath)
	if err != nil {
		return nil, fmt.Errorf("hash own binary: %w", err)
	}

	state := &registrationState{SelfPath: selfPath, SelfHash: selfHash}

	store, err := readDaemonStore(configPath)
	if err != nil {
		state.StoreReadErr = err
		return state, nil
	}
	for _, rb := range store.RegisteredBinaries {
		if rb.Path == selfPath {
			state.PathFound = true
			state.StoreHash = rb.Hash
			state.HashMatches = strings.EqualFold(rb.Hash, selfHash)
			break
		}
	}
	return state, nil
}

// checkRegistered asks the daemon binary whether we are registered and authorized
// for the AgentSecrets namespace. This is the daemon's own verdict on its store, so
// it works even when the store file itself is not readable by this user.
//
// It reports (registered, detail). A non-zero exit means "not registered" and the
// combined output carries the daemon's reason, which is surfaced in diagnostics.
func checkRegistered(keychainAuthPath, selfPath string) (bool, string) {
	if keychainAuthPath == "" || selfPath == "" {
		return false, "keychain-auth path or binary path unknown"
	}
	out, err := runProbe(keychainAuthPath, "check", selfPath, serviceName)
	detail := firstMeaningfulLine(string(out))
	if err != nil {
		return false, detail
	}
	return true, detail
}

// firstMeaningfulLine extracts the first informative line of a CLI's output,
// skipping cobra's usage boilerplate so diagnostics stay short and readable.
func firstMeaningfulLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Usage:") || strings.HasPrefix(line, "Flags:") {
			continue
		}
		return strings.TrimPrefix(line, "Error: ")
	}
	return ""
}

// runningDaemonBinary returns the executable path of the live keychain-auth process,
// or "" when it cannot be determined. A daemon started before an upgrade keeps
// serving the old code, so comparing this against the best on-disk binary is what
// detects a stale running daemon.
func runningDaemonBinary() string {
	_, exe := findDaemonProcess()
	return exe
}

// findDaemonProcess locates a live keychain-auth process and returns its PID and
// resolved executable path. It scans /proc on Linux and uses pgrep on macOS; on
// Windows the daemon runs as a named-pipe service and is not discovered this way.
func findDaemonProcess() (pid int, exePath string) {
	switch runtime.GOOS {
	case "linux":
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return 0, ""
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if name == "" || name[0] < '0' || name[0] > '9' {
				continue
			}
			p, err := strconv.Atoi(name)
			if err != nil {
				continue
			}
			// comm is world-readable, unlike exe: the daemon runs as its own user,
			// so its exe symlink cannot be resolved from an unprivileged client.
			comm, err := os.ReadFile(filepath.Join("/proc", name, "comm"))
			if err != nil || strings.TrimSpace(string(comm)) != "keychain-auth" {
				continue
			}
			exe, err := os.Readlink(filepath.Join("/proc", name, "exe"))
			if err != nil {
				exe = procCmdline0(name)
			}
			return p, exe
		}
		return 0, ""
	case "darwin":
		out, err := runProbe("pgrep", "-x", "keychain-auth")
		if err != nil {
			return 0, ""
		}
		p, err := strconv.Atoi(strings.TrimSpace(strings.Split(string(out), "\n")[0]))
		if err != nil || p <= 0 {
			return 0, ""
		}
		// `ps -o comm=` yields the executable path of the process on macOS.
		cmdOut, err := runProbe("ps", "-p", strconv.Itoa(p), "-o", "comm=")
		if err != nil {
			return p, ""
		}
		return p, strings.TrimSpace(string(cmdOut))
	default:
		return 0, ""
	}
}

// procCmdline0 returns the executable path recorded in /proc/<pid>/cmdline, which
// is readable even when the process belongs to another user.
func procCmdline0(pid string) string {
	data, err := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
	if err != nil {
		return ""
	}
	if i := bytes.IndexByte(data, 0); i >= 0 {
		data = data[:i]
	}
	return string(data)
}

// linuxSystemdManaged reports whether the running keychain-auth daemon is supervised
// by systemd. Restarting a systemd-managed daemon must go through systemctl; killing
// it out from under systemd fights its restart policy and leaves a window where the
// socket is down.
func linuxSystemdManaged() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	pid, _ := findDaemonProcess()
	if pid == 0 {
		return false
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), ".service")
}

// systemdUnitExists reports whether a keychain-auth systemd unit is installed.
func systemdUnitExists() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	for _, p := range []string{
		"/etc/systemd/system/keychain-auth.service",
		"/usr/lib/systemd/system/keychain-auth.service",
		"/lib/systemd/system/keychain-auth.service",
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}
