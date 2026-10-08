package keychainauth

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// AutoSetup performs the full keychain-auth setup sequence:
//  1. Ensures keychain-auth is installed (installs if missing)
//  2. Installs the system sandbox (system user, config, service) on Linux
//  3. Registers the AgentSecrets binary hash with keychain-auth
//  4. Ensures the daemon is running (starts if not)
//
// This is designed to be invisible to the user during normal operation.
// When called during an upgrade (first secret read after update), the caller
// should display a spinner and explanatory message.
//
// Returns nil if everything is ready, or an error describing what failed.
func AutoSetup() error {
	_ = PurgeLegacyFiles()

	kcPath, err := EnsureInstalled()
	if err != nil {
		return fmt.Errorf("keychain-auth setup: %w", err)
	}

	if runtime.GOOS == "linux" {
		if err := ensureSandboxInstalled(kcPath); err != nil {
			return fmt.Errorf("keychain-auth sandbox system setup: %w", err)
		}
	}

	if err := EnsureRegistered(kcPath); err != nil {
		return fmt.Errorf("keychain-auth setup: %w", err)
	}

	if err := EnsureDaemonRunning(kcPath); err != nil {
		return fmt.Errorf("keychain-auth setup: %w", err)
	}

	return nil
}

// RequiredDaemonVersion is the minimum keychain-auth daemon this build accepts,
// pinned to the daemon version co-released with it. Any older daemon fails the
// compareVersions check in EnsureInstalled and is upgraded to the latest release,
// so a daemon binary change always reaches users rather than leaving a stale
// daemon in place.
const RequiredDaemonVersion = "3.2.3"

// findBestDaemon returns the path to the highest-priority installed keychain-auth
// binary (mirroring EnsureInstalled's search order), or "" if none is found.
func findBestDaemon() string {
	homeDir, _ := os.UserHomeDir()
	binaryName := "keychain-auth"
	if runtime.GOOS == "windows" {
		binaryName = "keychain-auth.exe"
	}
	candidates := []string{}
	if runtime.GOOS == "linux" {
		candidates = append(candidates, "/usr/local/bin/keychain-auth")
	}
	candidates = append(candidates,
		filepath.Join(homeDir, "go", "bin", binaryName),
		filepath.Join(homeDir, ".local", "bin", binaryName),
	)
	if p, err := exec.LookPath(binaryName); err == nil {
		candidates = append(candidates, p)
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// DaemonUpdateNeeded reports whether the installed keychain-auth binary is
// missing or older than RequiredDaemonVersion. It is a cheap, read-only check
// (a stat plus one `--version` exec) used to gate the heavier EnsureDaemonUpToDate
// path — and its sudo prompt — so it only runs when an update is actually due.
func DaemonUpdateNeeded() bool {
	path := findBestDaemon()
	if path == "" {
		return true
	}
	v, err := queryInstalledVersion(path)
	if err != nil {
		return true
	}
	return compareVersions(v, RequiredDaemonVersion) < 0
}

// EnsureDaemonUpToDate installs or upgrades the keychain-auth daemon to at least
// RequiredDaemonVersion and, when an upgrade replaced the on-disk binary, restarts
// the running daemon so the new binary actually takes effect. brew upgrade only
// swaps the file; the previously-started daemon process keeps serving the old
// code until it is restarted. It is a no-op when the daemon is already current.
func EnsureDaemonUpToDate() error {
	if !DaemonUpdateNeeded() {
		return nil
	}
	// Install/upgrade the on-disk binary to RequiredDaemonVersion.
	if _, err := EnsureInstalled(); err != nil {
		return err
	}
	// The upgrade only swapped the file; a daemon started from the old binary is
	// still serving. Restart it so requests hit the new code. RestartDaemon kills
	// the old process, removes the stale socket, and starts the fresh binary.
	if err := RestartDaemon(); err != nil {
		return fmt.Errorf("keychain-auth upgraded but daemon restart failed: %w", err)
	}
	// Drop our now-dead connection to the old daemon so the next request re-dials
	// the freshly started one instead of erroring on a severed socket.
	Close()
	return nil
}

// findBrew locates the brew binary in PATH or standard installation directories.
func findBrew() string {
	if p, err := exec.LookPath("brew"); err == nil {
		return p
	}
	homeDir, _ := os.UserHomeDir()
	candidates := []string{
		"/home/linuxbrew/.linuxbrew/bin/brew",
		"/opt/homebrew/bin/brew",
		"/usr/local/bin/brew",
		filepath.Join(homeDir, ".linuxbrew", "bin", "brew"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// EnsureInstalled checks if keychain-auth is in PATH and matches the required version.
// If not found or outdated, attempts to install it via the platform's package manager.
// Returns the absolute path to the keychain-auth binary.
func EnsureInstalled() (string, error) {
	homeDir, _ := os.UserHomeDir()
	binaryName := "keychain-auth"
	if runtime.GOOS == "windows" {
		binaryName = "keychain-auth.exe"
	}

	// On Linux, prefer the system-wide installed binary at /usr/local/bin/keychain-auth
	// since the system daemon service runs it.
	if runtime.GOOS == "linux" {
		sysBinPath := "/usr/local/bin/keychain-auth"
		if _, err := os.Stat(sysBinPath); err == nil {
			if v, vErr := queryInstalledVersion(sysBinPath); vErr == nil && compareVersions(v, RequiredDaemonVersion) >= 0 {
				return sysBinPath, nil
			}
		}
	}

	goBinPath := filepath.Join(homeDir, "go", "bin", binaryName)

	// 1. Prefer our locally built binary in ~/go/bin
	if _, err := os.Stat(goBinPath); err == nil {
		if v, vErr := queryInstalledVersion(goBinPath); vErr == nil && compareVersions(v, RequiredDaemonVersion) >= 0 {
			return goBinPath, nil
		}
	}

	// 2. Check if already installed in PATH
	if path, err := exec.LookPath(binaryName); err == nil {
		if v, vErr := queryInstalledVersion(path); vErr == nil && compareVersions(v, RequiredDaemonVersion) >= 0 {
			return path, nil
		}
	}

	// Check common user-local bin paths if PATH isn't set up properly
	commonPaths := []string{
		"/home/linuxbrew/.linuxbrew/bin/keychain-auth",
		"/opt/homebrew/bin/keychain-auth",
		filepath.Join(homeDir, ".local", "bin", binaryName),
		filepath.Join(homeDir, ".linuxbrew", "bin", binaryName),
	}
	if runtime.GOOS != "windows" {
		commonPaths = append(commonPaths, "/usr/local/bin/keychain-auth")
	}
	for _, p := range commonPaths {
		if _, err := os.Stat(p); err == nil {
			if v, vErr := queryInstalledVersion(p); vErr == nil && compareVersions(v, RequiredDaemonVersion) >= 0 {
				return p, nil
			}
		}
	}

	// Not installed or outdated — attempt platform-specific installation.
	// alreadyPresent distinguishes "outdated, on disk" (needs `brew upgrade`)
	// from "missing" (needs `brew install`); `brew install` is a no-op on an
	// already-installed formula and would leave a stale daemon in place.
	alreadyPresent := keychainAuthOnDisk()
	switch runtime.GOOS {
	case "darwin":
		return installViaBrew(alreadyPresent)
	case "linux":
		// Try Homebrew first (Linuxbrew), then fall back to instructions
		if brewPath := findBrew(); brewPath != "" {
			return installViaBrew(alreadyPresent)
		}
		return "", fmt.Errorf(
			"keychain-auth is not installed.\n\n" +
				"Install it with Homebrew:\n" +
				"  brew install The-17/tap/keychain-auth\n\n" +
				"Or download from GitHub:\n" +
				"  https://github.com/The-17/keychain-auth/releases",
		)
	case "windows":
		return "", fmt.Errorf(
			"keychain-auth is not installed.\n\n" +
				"Build it from source:\n" +
				"  go install github.com/The-17/keychain-auth/cmd/keychain-auth@latest\n\n" +
				"Or download the Windows release from GitHub:\n" +
				"  https://github.com/The-17/keychain-auth/releases",
		)
	default:
		return "", fmt.Errorf("keychain-auth is not supported on %s yet", runtime.GOOS)
	}
}

// keychainAuthOnDisk reports whether keychain-auth is installed anywhere (any
// version), used to distinguish "outdated" from "missing" so installViaBrew
// knows whether to `brew upgrade` (for an outdated formula) or `brew install`.
func keychainAuthOnDisk() bool {
	if _, err := exec.LookPath("keychain-auth"); err == nil {
		return true
	}
	// Check common paths even if not in PATH
	homeDir, _ := os.UserHomeDir()
	candidates := []string{
		"/home/linuxbrew/.linuxbrew/bin/keychain-auth",
		"/opt/homebrew/bin/keychain-auth",
		filepath.Join(homeDir, "go", "bin", "keychain-auth"),
		filepath.Join(homeDir, ".local", "bin", "keychain-auth"),
		filepath.Join(homeDir, ".linuxbrew", "bin", "keychain-auth"),
		"/usr/local/bin/keychain-auth",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// installViaBrew installs or upgrades keychain-auth via Homebrew. alreadyPresent
// distinguishes an outdated install (needs `brew upgrade`) from a missing one
// (needs `brew install`); `brew install` is a no-op on an already-installed
// formula and would leave a stale daemon in place.
func installViaBrew(alreadyPresent bool) (string, error) {
	brewPath := findBrew()
	if brewPath == "" {
		return "", fmt.Errorf("brew not found")
	}
	var cmd *exec.Cmd
	if alreadyPresent {
		cmd = exec.Command(brewPath, "upgrade", "The-17/tap/keychain-auth")
	} else {
		cmd = exec.Command(brewPath, "install", "The-17/tap/keychain-auth")
	}
	cmd.Env = append(os.Environ(), "HOMEBREW_NO_SANDBOX=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf(
			"failed to install keychain-auth via Homebrew: %w\n\n"+
				"You can install it manually:\n"+
				"  brew tap The-17/tap\n"+
				"  brew install keychain-auth",
			err,
		)
	}

	// Find the installed binary
	homeDir, _ := os.UserHomeDir()
	binaryName := "keychain-auth"
	candidates := []string{
		"/home/linuxbrew/.linuxbrew/bin/keychain-auth",
		"/opt/homebrew/bin/keychain-auth",
		"/usr/local/bin/keychain-auth",
		filepath.Join(homeDir, ".linuxbrew", "bin", "keychain-auth"),
		filepath.Join(homeDir, "go", "bin", binaryName),
		filepath.Join(homeDir, ".local", "bin", binaryName),
	}
	var path string
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			path = p
			break
		}
	}
	if path == "" {
		var err error
		path, err = exec.LookPath("keychain-auth")
		if err != nil {
			return "", fmt.Errorf("keychain-auth installed but not found in PATH or standard directories: %w", err)
		}
	}

	// Verify the installed version now meets the requirement
	installedVer, verErr := queryInstalledVersion(path)
	if verErr != nil || compareVersions(installedVer, RequiredDaemonVersion) < 0 {
		return "", fmt.Errorf(
			"keychain-auth was installed but is still version %s, below required %s.\n"+
				"Try updating Homebrew and re-running:\n"+
				"  brew update\n"+
				"  brew upgrade The-17/tap/keychain-auth",
			installedVer, RequiredDaemonVersion,
		)
	}
	return path, nil
}

// IsFullyConfigured reports whether this binary is not merely connected but
// actually accepted by the daemon — i.e. registered with a hash that matches.
// A connect-only check is insufficient: the daemon accepts the socket connection
// even for an unregistered binary and only denies at request time, so we issue
// one verification request. This is what lets EnsureRegistered detect a freshly
// upgraded (and therefore unregistered) binary and re-authorize it, rather than
// short-circuiting on a successful-but-unverified connection.
func IsFullyConfigured() bool {
	if err := Init(); err != nil {
		return false
	}
	return Verify() == nil
}

// EnsureRegistered registers the current AgentSecrets binary with keychain-auth.
// This tells keychain-auth "this binary is trusted" by recording its SHA-256 hash.
//
// On upgrade, the new hash must be registered before the first secret read.
// This function is idempotent — re-registering the same hash is a no-op.
func EnsureRegistered(keychainAuthPath string) error {
	if IsFullyConfigured() {
		return nil
	}

	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine own binary path: %w", err)
	}
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		return fmt.Errorf("cannot resolve binary symlinks: %w", err)
	}

	var cmd *exec.Cmd
	if requiresSudoForRegistration(keychainAuthPath) {
		cmd = exec.Command("sudo", keychainAuthPath, "authorize", selfPath, serviceName)
		cmd.Stdin = os.Stdin
	} else {
		cmd = exec.Command(keychainAuthPath, "authorize", selfPath, serviceName)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to authorize binary with keychain-auth: %w\nOutput: %s", err, strings.TrimSpace(string(output)))
	}

	if requiresSudoForRegistration(keychainAuthPath) {
		_ = exec.Command("sudo", "chmod", "644", "/etc/keychain-auth/config.json").Run()
	}

	return nil
}

func requiresSudoForRegistration(keychainAuthPath string) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	// Query keychain-auth status command
	cmd := exec.Command(keychainAuthPath, "status", "--json")
	output, err := cmd.Output()
	if err == nil {
		var status struct {
			RequiresSudo bool `json:"requires_sudo"`
		}
		if json.Unmarshal(output, &status) == nil {
			return status.RequiresSudo
		}
	}
	// Fallback to checking socket path
	return SocketPath() == "/run/keychain-auth/agent.sock"
}

// EnsureDaemonRunning checks if the keychain-auth daemon is running by probing
// the socket/pipe. If it doesn't exist, it attempts to start the daemon.
func EnsureDaemonRunning(keychainAuthPath string) error {
	if IsAvailable() {
		return nil
	}

	switch runtime.GOOS {
	case "windows":
		return startDirect(keychainAuthPath)
	case "darwin":
		return startDaemonMacOS(keychainAuthPath)
	case "linux":
		return startDaemonLinux(keychainAuthPath)
	default:
		return fmt.Errorf("cannot start keychain-auth daemon on %s", runtime.GOOS)
	}
}

// RestartDaemon kills any running keychain-auth daemon and starts a fresh one.
// This is needed after re-registering a binary so the daemon picks up the new hash.
func RestartDaemon() error {
	if runtime.GOOS == "windows" {
		// On Windows, kill the process by name
		_ = exec.Command("taskkill", "/F", "/IM", "keychain-auth.exe").Run()
	} else {
		// Kill existing daemon
		_ = exec.Command("pkill", "-x", "keychain-auth").Run()
		// Remove stale socket
		sockPath := SocketPath()
		_ = os.Remove(sockPath)
	}

	// Wait a moment for the process to die
	time.Sleep(200 * time.Millisecond)

	// Find keychain-auth and start fresh
	kcPath, err := EnsureInstalled()
	if err != nil {
		return fmt.Errorf("keychain-auth not found: %w", err)
	}
	return startDirect(kcPath)
}

// startDaemonMacOS starts keychain-auth via launchctl on macOS.
func startDaemonMacOS(keychainAuthPath string) error {
	// Try launchctl first (preferred — survives reboots)
	plistName := "io.keychainauth.daemon"
	cmd := exec.Command("launchctl", "start", plistName)
	if err := cmd.Run(); err == nil {
		return waitForSocket()
	}

	// Fallback: try loading the plist if it exists
	home, _ := os.UserHomeDir()
	plistPath := home + "/Library/LaunchAgents/" + plistName + ".plist"
	if _, err := os.Stat(plistPath); err == nil {
		cmd = exec.Command("launchctl", "load", plistPath)
		if err := cmd.Run(); err == nil {
			return waitForSocket()
		}
	}

	// Last resort: start directly
	return startDirect(keychainAuthPath)
}

// startDaemonLinux starts keychain-auth via systemd on Linux.
func startDaemonLinux(keychainAuthPath string) error {
	// Try systemd system service first (dedicated system user sandbox daemon)
	if _, err := os.Stat("/run/keychain-auth"); err == nil {
		cmd := exec.Command("systemctl", "start", "keychain-auth")
		if err := cmd.Run(); err == nil {
			return waitForSocketPath("/run/keychain-auth/agent.sock")
		}
		// Fallback with sudo
		cmd = exec.Command("sudo", "systemctl", "start", "keychain-auth")
		cmd.Stdin = os.Stdin
		if err := cmd.Run(); err == nil {
			return waitForSocketPath("/run/keychain-auth/agent.sock")
		}
	}

	// Fallback to systemd user service (user-space legacy daemon)
	cmd := exec.Command("systemctl", "--user", "start", "keychain-auth")
	if err := cmd.Run(); err == nil {
		return waitForSocketPath(UserSocketPath())
	}

	// Try enabling and starting user service
	cmd = exec.Command("systemctl", "--user", "enable", "--now", "keychain-auth")
	if err := cmd.Run(); err == nil {
		return waitForSocketPath(UserSocketPath())
	}

	// Last resort: start directly
	return startDirect(keychainAuthPath)
}

// startDirect starts keychain-auth as a background process. This is the fallback
// when the system service manager is not configured.
func startDirect(keychainAuthPath string) error {
	sockPath := UserSocketPath()

	if runtime.GOOS != "windows" {
		_ = os.Remove(sockPath)
		// Ensure the socket directory exists
		if err := os.MkdirAll(filepath.Dir(sockPath), 0700); err != nil {
			return fmt.Errorf("failed to create socket directory: %w", err)
		}
	}

	// Pass --socket so even older keychain-auth binaries that default to
	// /var/run/ will use the user-writable path instead.
	cmd := exec.Command(keychainAuthPath, "start", "--socket", sockPath)

	var logDir string
	if home, err := os.UserHomeDir(); err == nil {
		if runtime.GOOS == "windows" {
			logDir = filepath.Join(home, "AppData", "Local", "keychain-auth")
		} else {
			logDir = filepath.Join(home, ".config", "keychain-auth")
		}
	} else {
		logDir = os.TempDir()
	}
	_ = os.MkdirAll(logDir, 0700)
	logFile, _ := os.OpenFile(filepath.Join(logDir, "daemon.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)

	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil

	// Start in a new session so the daemon survives parent CLI exit
	setSysProcAttr(cmd)

	// Start as detached process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start keychain-auth daemon: %w", err)
	}

	// Don't wait for the process — it's a daemon
	go func() { _ = cmd.Wait() }()

	return waitForSocketPath(sockPath)
}

// waitForSocketPath polls for a specific socket file/named pipe to appear and be dialable, with an 8-second timeout.
func waitForSocketPath(sockPath string) error {
	for i := 0; i < 80; i++ {
		c, err := dialCLOEXEC(sockPath)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("keychain-auth daemon started but socket/pipe at %s not available after 8 seconds", sockPath)
}

// waitForSocket polls for the default socket file/named pipe to appear and be dialable.
func waitForSocket() error {
	return waitForSocketPath(SocketPath())
}

// PurgeLegacyFiles overwrites legacy keyring.json files with random bytes and deletes them.
func PurgeLegacyFiles() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	paths := []string{
		filepath.Join(home, ".agentsecrets", "keyring.json"),
		filepath.Join(home, ".keychain-auth", "keyring.json"),
		// keyring_file.json: the pre-v3 file-based keyring fallback. It was renamed from
		// keyring.json during the v3 transition to avoid accidental deletion, but v3 removed
		// the file-based fallback entirely. Any copy on disk is a stale credential store that
		// must be shredded. Added in v3.0.1.
		filepath.Join(home, ".agentsecrets", "keyring_file.json"),
	}

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue // file doesn't exist, skip
		}
		if info.IsDir() {
			continue
		}

		size := info.Size()
		if size <= 0 {
			size = 1024
		}

		// Shred file by overwriting it with random bytes
		f, err := os.OpenFile(p, os.O_WRONLY, 0600)
		if err != nil {
			_ = os.Remove(p)
			continue
		}

		randBytes := make([]byte, size)
		if _, randErr := rand.Read(randBytes); randErr == nil {
			_, _ = f.Write(randBytes)
			_ = f.Sync()
		}
		f.Close()
		_ = os.Remove(p)
	}

	// Purge stale Windows Credential Manager entries if running under WSL
	purgeLegacyWCMEntries()

	return nil
}

// purgeLegacyWCMEntries purges stale Windows Credential Manager entries starting with "AgentSecrets:"
// when running under WSL (since system-mode daemon stores everything locally in WSL instead of WCM).
func purgeLegacyWCMEntries() {
	if runtime.GOOS != "linux" {
		return
	}
	cmdkeyPath, err := exec.LookPath("cmdkey.exe")
	if err != nil {
		if _, statErr := os.Stat("/mnt/c/Windows/system32/cmdkey.exe"); statErr == nil {
			cmdkeyPath = "/mnt/c/Windows/system32/cmdkey.exe"
		} else {
			return
		}
	}

	cmd := exec.Command(cmdkeyPath, "/list")
	out, err := cmd.Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(out), "\n")
	var targets []string
	for _, line := range lines {
		if strings.Contains(line, "target=AgentSecrets:") {
			idx := strings.Index(line, "target=")
			if idx != -1 {
				target := strings.TrimSpace(line[idx+7:])
				targets = append(targets, target)
			}
		}
	}

	for _, target := range targets {
		_ = exec.Command(cmdkeyPath, "/delete:"+target).Run()
	}
}

// queryInstalledVersion returns the version of the installed keychain-auth daemon.
func queryInstalledVersion(binPath string) (string, error) {
	cmd := exec.Command(binPath, "--version")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return "", fmt.Errorf("empty version output")
	}
	return fields[len(fields)-1], nil
}

// compareVersions parses simple semver (e.g. "2.2.0") and returns:
//
//	-1 if v1 < v2
//	 0 if v1 == v2
//	 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	if v1 == "dev" || v1 == "vdev" {
		return 0
	}
	v1 = strings.TrimPrefix(v1, "v")
	v2 = strings.TrimPrefix(v2, "v")

	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	for i := 0; i < 3; i++ {
		var n1, n2 int
		if i < len(parts1) {
			_, _ = fmt.Sscanf(parts1[i], "%d", &n1)
		}
		if i < len(parts2) {
			_, _ = fmt.Sscanf(parts2[i], "%d", &n2)
		}
		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}
	return 0
}
func ensureSandboxInstalled(keychainAuthPath string) error {
	// Ensure config directory exists
	if f, err := os.Open("/etc/keychain-auth/config.json"); err == nil {
		f.Close()
		return nil
	}

	// Run install command via sudo
	cmd := exec.Command("sudo", keychainAuthPath, "install")
	cmd.Stdin = os.Stdin
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("keychain-auth system installer command failed: %w\nOutput: %s", err, string(output))
	}

	_ = exec.Command("sudo", "chmod", "644", "/etc/keychain-auth/config.json").Run()
	return nil
}
