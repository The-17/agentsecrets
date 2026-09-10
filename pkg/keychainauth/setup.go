package keychainauth

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// runSudo runs a privileged command NON-INTERACTIVELY.
//
// sudo is always invoked with -n so it reuses a credential the caller has already
// cached, and never blocks on a password prompt. This matters because privileged
// steps run behind a spinner: an interactive sudo prompt there is invisible, so the
// command appears to hang (it is actually waiting for input nobody can see).
//
// The caller is responsible for caching a credential first — the command layer runs
// `sudo -v` once before any privileged work, so the whole update/re-authorize
// sequence shares a single authorization. If the credential is missing or has
// lapsed, this fails immediately with an actionable message rather than hanging.
//
// The timeout additionally guards against a wedged systemd or filesystem.
func runSudo(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", append([]string{"-n"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return out, nil
	}
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("`sudo %s` timed out after %s", strings.Join(args, " "), timeout)
	}
	msg := strings.TrimSpace(string(out))
	if strings.Contains(msg, "password is required") || strings.Contains(msg, "a terminal is required") {
		return out, fmt.Errorf("administrator authorization is required; re-run the command and enter your password when prompted")
	}
	return out, fmt.Errorf("`sudo %s` failed: %w (%s)", strings.Join(args, " "), err, msg)
}

// ensureSystemDaemonBinary installs kcPath as the binary a systemd unit runs
// (/usr/local/bin/keychain-auth). On other setups the daemon runs kcPath directly,
// so there is nothing to promote.
func ensureSystemDaemonBinary(kcPath string) error {
	if runtime.GOOS != "linux" || !systemdUnitExists() {
		return nil
	}
	sysBinPath := "/usr/local/bin/keychain-auth"
	if kcPath == sysBinPath {
		return nil
	}
	if err := promoteBinaryTo(kcPath, sysBinPath); err != nil {
		return fmt.Errorf("installing keychain-auth to %s: %w", sysBinPath, err)
	}
	return nil
}

// promoteBinaryTo installs src as a system binary at dst using a temporary file and
// an atomic rename, so the daemon never sees a half-written executable (overwriting
// a running binary in place can fail with ETXTBSY). Used on the Linux path where the
// systemd unit runs a system-path binary but the freshly downloaded one lands in the
// user's home directory.
func promoteBinaryTo(src, dst string) error {
	tmp := dst + ".new"
	if _, err := runSudo(60*time.Second, "cp", src, tmp); err != nil {
		return err
	}
	if _, err := runSudo(20*time.Second, "chmod", "755", tmp); err != nil {
		return err
	}
	if _, err := runSudo(20*time.Second, "mv", "-f", tmp, dst); err != nil {
		return err
	}
	return nil
}

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
const RequiredDaemonVersion = "3.3.0"

// candidateDaemonPaths returns all standard filesystem and PATH locations where keychain-auth can reside across all operating systems.
func candidateDaemonPaths() []string {
	homeDir, _ := os.UserHomeDir()
	binaryName := "keychain-auth"
	if runtime.GOOS == "windows" {
		binaryName = "keychain-auth.exe"
	}
	candidates := []string{}
	if runtime.GOOS == "linux" {
		candidates = append(candidates, "/usr/local/bin/keychain-auth", "/usr/bin/keychain-auth")
	} else if runtime.GOOS == "darwin" {
		candidates = append(candidates, "/opt/homebrew/bin/keychain-auth", "/usr/local/bin/keychain-auth")
	}
	candidates = append(candidates,
		filepath.Join(homeDir, ".agentsecrets", "bin", binaryName),
		filepath.Join(homeDir, "go", "bin", binaryName),
		filepath.Join(homeDir, ".local", "bin", binaryName),
		filepath.Join(homeDir, ".linuxbrew", "bin", binaryName),
		"/home/linuxbrew/.linuxbrew/bin/keychain-auth",
	)
	if p, err := exec.LookPath(binaryName); err == nil {
		candidates = append(candidates, p)
	}
	return candidates
}

// findBestDaemon returns the path to the highest-priority installed keychain-auth
// binary (mirroring EnsureInstalled's search order), or "" if none is found.
func findBestDaemon() string {
	var firstFound string
	for _, p := range candidateDaemonPaths() {
		if _, err := os.Stat(p); err == nil {
			if firstFound == "" {
				firstFound = p
			}
			if v, vErr := queryInstalledVersion(p); vErr == nil && compareVersions(v, RequiredDaemonVersion) >= 0 {
				return p
			}
		}
	}
	return firstFound
}

// DaemonUpdateNeeded reports whether an update is due: the installed keychain-auth
// binary is missing or older than RequiredDaemonVersion, OR the currently running
// daemon process is older than the required version.
//
// The running-process check matters because a daemon started before an upgrade
// keeps serving the old code even after the on-disk binary is replaced (and an
// interrupted upgrade can leave a stale process behind with no on-disk counterpart
// at the offending version). It is a cheap, read-only check — a stat plus one or two
// `--version` execs — that gates the heavier EnsureDaemonUpToDate path and its sudo
// prompt, so it only runs when an update is actually due.
func DaemonUpdateNeeded() bool {
	path := findBestDaemon()
	if path == "" {
		return true
	}
	v, err := queryInstalledVersion(path)
	if err != nil {
		return true
	}
	if compareVersions(v, RequiredDaemonVersion) < 0 {
		return true
	}
	// On-disk binary is current, but the running process may predate it.
	if running := runningDaemonBinary(); running != "" && running != path {
		if rv, rerr := queryInstalledVersion(running); rerr == nil {
			if compareVersions(rv, RequiredDaemonVersion) < 0 {
				return true
			}
		}
	}
	return false
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
	kcPath, err := EnsureInstalled()
	if err != nil {
		return err
	}
	// Update the system binary the systemd unit runs, before the restart below.
	if err := ensureSystemDaemonBinary(kcPath); err != nil {
		return err
	}
	// The upgrade replaced the binary; restart the daemon so it reloads it.
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

// manualDaemonInstallHint returns OS-appropriate instructions for installing or
// updating keychain-auth by hand, for the messages shown when automatic installation
// fails.
//
// The GitHub release download is listed for every platform: it is how the automatic
// installer fetches the binary (the release asset is built per OS/arch), and it is
// the only option on Windows. Homebrew is offered only where brew is actually
// present, so the guidance is never a dead end on a platform that has no brew.
func manualDaemonInstallHint() string {
	hint := "  Download the release for your platform from GitHub:\n" +
		"  https://github.com/The-17/keychain-auth/releases"
	if runtime.GOOS != "windows" && findBrew() != "" {
		hint = "  brew upgrade The-17/tap/keychain-auth\n\n" + hint
	}
	return hint
}

// EnsureInstalled checks if keychain-auth is in PATH and matches the required version.
// If not found or outdated, attempts automated multi-tiered installation.
// Returns the absolute path to the keychain-auth binary.
func EnsureInstalled() (string, error) {
	homeDir, _ := os.UserHomeDir()
	binaryName := "keychain-auth"
	if runtime.GOOS == "windows" {
		binaryName = "keychain-auth.exe"
	}

	agentSecretsBinPath := filepath.Join(homeDir, ".agentsecrets", "bin", binaryName)

	// Check if already installed in any candidate path with required version
	for _, p := range candidateDaemonPaths() {
		if _, err := os.Stat(p); err == nil {
			if v, vErr := queryInstalledVersion(p); vErr == nil && compareVersions(v, RequiredDaemonVersion) >= 0 {
				return p, nil
			}
		}
	}

	// Tier 1: Direct Download from GitHub Releases into ~/.agentsecrets/bin/ (Fastest: <500ms)
	if path, err := downloadFromGitHub(agentSecretsBinPath); err == nil {
		v, vErr := queryInstalledVersion(path)
		if vErr == nil && compareVersions(v, RequiredDaemonVersion) >= 0 {
			// On Linux, if system daemon is installed at standard system paths, update it too
			if runtime.GOOS == "linux" {
				for _, sysPath := range []string{"/usr/local/bin/keychain-auth", "/usr/bin/keychain-auth"} {
					if _, statErr := os.Stat(sysPath); statErr == nil {
						if promoteBinaryTo(path, sysPath) == nil {
							if vSys, vSysErr := queryInstalledVersion(sysPath); vSysErr == nil && compareVersions(vSys, RequiredDaemonVersion) >= 0 {
								return sysPath, nil
							}
						}
					}
				}
			}
		}
		// Use the freshly downloaded release even when it predates RequiredDaemonVersion
		// (the pinned version is not published yet): a working daemon beats falling
		// through to a heavier installer. The version gate still reports it as due.
		return path, nil
	}

	// Tier 2: Try Homebrew (macOS / Linuxbrew)
	if brewPath := findBrew(); brewPath != "" {
		if path, err := installViaBrew(); err == nil {
			return path, nil
		}
	}

	// There is deliberately no "build from source" tier. `go install @latest` is
	// the wrong tool for this: it compiles at an arbitrary `@latest` (which does not
	// honour RequiredDaemonVersion), needs a Go toolchain, and can pull an unrelated
	// version of the module. Running that silently inside a routine command is how a
	// user ends up watching a CLI download a Go compiler. If the release binary
	// could not be fetched, say so clearly instead.
	return "", fmt.Errorf(
		"keychain-auth v%s could not be installed automatically.\n\n"+
			"Install it manually, then run the command again:\n%s",
		RequiredDaemonVersion, manualDaemonInstallHint(),
	)
}

// downloadFromGitHub downloads and unpacks the keychain-auth binary release
// directly from GitHub, preferring the exact RequiredDaemonVersion and falling back
// to the latest published release when the pinned one is not out yet.
//
// The fallback matters during a coordinated release window: this build may pin a
// daemon version whose release is not yet published. In that case the newest
// published release is installed rather than failing — a working daemon beats a
// hard error, and the caller's version gate still reports that a newer daemon is
// due. There is no build-from-source fallback.
func downloadFromGitHub(targetPath string) (string, error) {
	// The common case: the pinned version is released — one request, no API call.
	if err := fetchReleaseBinary(targetPath, RequiredDaemonVersion); err == nil {
		return targetPath, nil
	}

	// Pinned version not published (yet): use the newest published release.
	latest, err := latestReleasedVersion()
	if err != nil {
		return "", fmt.Errorf("keychain-auth v%s is not released and the latest release could not be resolved: %w",
			RequiredDaemonVersion, err)
	}
	if err := fetchReleaseBinary(targetPath, latest); err != nil {
		return "", err
	}
	return targetPath, nil
}

// fetchReleaseBinary downloads the release archive for a specific version and
// unpacks the keychain-auth binary into targetPath.
func fetchReleaseBinary(targetPath, version string) error {
	osName := runtime.GOOS
	archName := runtime.GOARCH
	archiveExt := "tar.gz"
	binaryName := "keychain-auth"
	if osName == "windows" {
		binaryName = "keychain-auth.exe"
	}

	assetName := fmt.Sprintf("keychain-auth_%s_%s_%s.%s", version, osName, archName, archiveExt)
	downloadURL := fmt.Sprintf("https://github.com/The-17/keychain-auth/releases/download/v%s/%s", version, assetName)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github release download returned HTTP status %d for %s", resp.StatusCode, downloadURL)
	}

	targetDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create bin directory: %w", err)
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read gzip archive: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed reading tar stream: %w", err)
		}

		cleanName := filepath.Base(header.Name)
		if cleanName == binaryName {
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return fmt.Errorf("failed to open output binary file: %w", err)
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to write binary data: %w", err)
			}
			outFile.Close()
			return nil
		}
	}

	return fmt.Errorf("binary %s not found in release archive", binaryName)
}

// latestReleasedVersion resolves the newest published keychain-auth release via the
// GitHub API (e.g. "3.2.5"). Returns an error if it cannot be determined.
func latestReleasedVersion() (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/The-17/keychain-auth/releases/latest")
	if err != nil {
		return "", fmt.Errorf("query latest keychain-auth release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github API returned HTTP %d for the latest keychain-auth release", resp.StatusCode)
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", fmt.Errorf("parse latest keychain-auth release: %w", err)
	}
	return strings.TrimPrefix(rel.TagName, "v"), nil
}

func isBrewFormulaInstalled(brewPath string) bool {
	if brewPath == "" {
		return false
	}
	if err := exec.Command(brewPath, "list", "The-17/tap/keychain-auth").Run(); err == nil {
		return true
	}
	return exec.Command(brewPath, "list", "keychain-auth").Run() == nil
}

// installViaBrew installs or upgrades keychain-auth via Homebrew.
func installViaBrew() (string, error) {
	brewPath := findBrew()
	if brewPath == "" {
		return "", fmt.Errorf("brew not found")
	}
	alreadyPresent := isBrewFormulaInstalled(brewPath)
	var cmd *exec.Cmd
	if alreadyPresent {
		cmd = exec.Command(brewPath, "upgrade", "The-17/tap/keychain-auth")
	} else {
		cmd = exec.Command(brewPath, "install", "The-17/tap/keychain-auth")
	}
	cmd.Env = append(os.Environ(),
		"HOMEBREW_NO_AUTO_UPDATE=1",
		"HOMEBREW_NO_ENV_HINTS=1",
		"HOMEBREW_NO_SANDBOX=1",
	)
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
//
// Registration is only half the job. Authorizing writes the daemon's trust store,
// but a daemon that is already running keeps its previous policy in memory and will
// keep denying a binary the store now approves. So after a successful authorize we
// restart the daemon to activate the new policy, then verify the daemon really does
// accept us — rather than reporting success and failing on the user's next command.
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

	if err := authorizeBinary(keychainAuthPath, selfPath); err != nil {
		return err
	}

	// Activate the freshly written policy in the running daemon.
	if err := RestartDaemon(); err != nil {
		return fmt.Errorf("authorized %s but the daemon could not be restarted to apply it: %w", selfPath, err)
	}

	// Our old connection pointed at the pre-restart daemon.
	Close()

	// Prove the daemon now accepts this binary instead of assuming it does.
	if err := Init(); err != nil {
		return fmt.Errorf("authorized %s but could not reconnect to the daemon: %w", selfPath, err)
	}
	if err := probeDaemonGrant(); err != nil {
		return fmt.Errorf("authorized %s but the daemon still denies it: %w", selfPath, err)
	}
	return nil
}

// authorizeBinary runs keychain-auth's authorize command for selfPath, elevating
// only when the daemon reports that its store requires it.
//
// The privileged form goes through runSudo, so it reuses the credential the command
// layer has already cached (single prompt for the whole operation) and cannot block
// on an invisible password prompt. The binary is invoked by its resolved absolute
// path: keychain-auth is commonly installed under ~/.agentsecrets/bin, which is not
// in sudo's secure_path, so a bare `sudo keychain-auth` would fail with "command not
// found".
func authorizeBinary(keychainAuthPath, selfPath string) error {
	var (
		output []byte
		err    error
	)
	if requiresSudoForRegistration(keychainAuthPath) {
		output, err = runSudo(120*time.Second, keychainAuthPath, "authorize", selfPath, serviceName)
	} else {
		output, err = exec.Command(keychainAuthPath, "authorize", selfPath, serviceName).CombinedOutput()
	}
	if err == nil {
		return nil
	}

	outStr := strings.TrimSpace(string(output))
	if strings.Contains(outStr, "unknown command \"authorize\"") || strings.Contains(outStr, "unknown command") {
		return fmt.Errorf(
			"the installed keychain-auth binary (%s) is outdated and lacks the 'authorize' command.\n\n"+
				"Update it to v%s or higher, then run 'agentsecrets doctor':\n%s",
			keychainAuthPath, RequiredDaemonVersion, manualDaemonInstallHint(),
		)
	}
	return fmt.Errorf("failed to authorize binary with keychain-auth: %w\nOutput: %s", err, outStr)
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

// RestartDaemon restarts the running keychain-auth daemon so it reloads its trust
// store (a freshly authorized binary's hash) or its on-disk binary after an
// upgrade.
//
// Restart must reproduce how the daemon is actually running:
//   - A daemon supervised by systemd is restarted through systemctl and never
//     killed directly — killing it out from under systemd fights the unit's
//     restart policy and can leave the socket down while systemd backs off.
//   - A daemon that is NOT systemd-supervised (user-mode fallback, WSL without
//     systemd) is killed and relaunched in user mode.
func RestartDaemon() error {
	if runtime.GOOS == "windows" {
		// On Windows, kill the process by name.
		_ = exec.Command("taskkill", "/F", "/IM", "keychain-auth.exe").Run()
	} else if runtime.GOOS == "linux" && (linuxSystemdManaged() || systemdUnitExists()) {
		// systemd supervises the daemon (it is running under a unit, or a unit is
		// installed and waiting to start). systemctl restart handles stop+start and
		// honours the unit's User= and RuntimeDirectory=.
		if _, err := runSudo(60*time.Second, "systemctl", "restart", "keychain-auth"); err != nil {
			return fmt.Errorf("restart keychain-auth via systemd: %w", err)
		}
		// Our old connection pointed at the pre-restart daemon.
		Close()
		// systemd services can take longer than a direct start to come back up
		// (unit activation, daemon initialisation), so allow more time here than
		// waitForSocketPath does.
		return waitForSocketPathTimeout("/run/keychain-auth/agent.sock", restartSocketAttempts)
	} else {
		// No systemd supervision (macOS, or a user-mode daemon): kill any existing
		// daemon and remove a stale socket before relaunching.
		_ = exec.Command("pkill", "-x", "keychain-auth").Run()
		sockPath := SocketPath()
		_ = os.Remove(sockPath)
	}

	// Wait a moment for the process to die.
	time.Sleep(200 * time.Millisecond)

	// Find keychain-auth and restart via the platform-appropriate method.
	kcPath, err := EnsureInstalled()
	if err != nil {
		return fmt.Errorf("keychain-auth not found: %w", err)
	}

	switch runtime.GOOS {
	case "darwin":
		return startDaemonMacOS(kcPath)
	case "linux":
		return startDaemonLinux(kcPath)
	default:
		return startDirect(kcPath)
	}
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

// isSocketDialable returns true if the specified unix socket / pipe can be connected to immediately.
func isSocketDialable(sockPath string) bool {
	c, err := dialCLOEXEC(sockPath)
	if err == nil {
		c.Close()
		return true
	}
	return false
}

// startDaemonLinux starts or restarts keychain-auth via systemd on Linux.
func startDaemonLinux(keychainAuthPath string) error {
	sysSocket := "/run/keychain-auth/agent.sock"

	// Try systemd system service first (dedicated system user sandbox daemon)
	hasSystemdUnit := false
	if _, err := os.Stat("/etc/systemd/system/keychain-auth.service"); err == nil {
		hasSystemdUnit = true
	} else if _, err := os.Stat("/lib/systemd/system/keychain-auth.service"); err == nil {
		hasSystemdUnit = true
	} else if _, err := os.Stat("/run/keychain-auth"); err == nil {
		hasSystemdUnit = true
	}

	if hasSystemdUnit {
		// If system daemon socket is already active & dialable, attempt restart
		if isSocketDialable(sysSocket) {
			_ = exec.Command("systemctl", "restart", "keychain-auth").Run()
			_, _ = runSudo(60*time.Second, "systemctl", "restart", "keychain-auth")
			if isSocketDialable(sysSocket) {
				return nil
			}
		}

		cmd := exec.Command("systemctl", "restart", "keychain-auth")
		if err := cmd.Run(); err == nil {
			if err := waitForSocketPath(sysSocket); err == nil {
				return nil
			}
		}
		// Fallback with sudo
		if _, err := runSudo(60*time.Second, "systemctl", "restart", "keychain-auth"); err == nil {
			if err := waitForSocketPath(sysSocket); err == nil {
				return nil
			}
		}

		if isSocketDialable(sysSocket) {
			return nil
		}
	}

	// Fallback to systemd user service (user-space legacy daemon)
	cmd := exec.Command("systemctl", "--user", "restart", "keychain-auth")
	if err := cmd.Run(); err == nil {
		if err := waitForSocketPath(UserSocketPath()); err == nil {
			return nil
		}
	}

	// Try enabling and starting user service
	cmd = exec.Command("systemctl", "--user", "enable", "--now", "keychain-auth")
	if err := cmd.Run(); err == nil {
		if err := waitForSocketPath(UserSocketPath()); err == nil {
			return nil
		}
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
		} else if runtime.GOOS == "darwin" {
			logDir = filepath.Join(home, "Library", "Application Support", "keychain-auth")
		} else {
			logDir = filepath.Join(home, ".config", "keychain-auth")
			// Set user XDG paths so user-mode fallback daemon on Linux writes audit logs to ~/.agentsecrets/
			cmd.Env = append(os.Environ(),
				"XDG_DATA_HOME="+filepath.Join(home, ".agentsecrets"),
				"XDG_CONFIG_HOME="+filepath.Join(home, ".agentsecrets"),
			)
		}
	} else {
		logDir = os.TempDir()
	}
	_ = os.MkdirAll(logDir, 0700)
	logFile, _ := os.OpenFile(filepath.Join(logDir, "daemon.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)

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
	return waitForSocketPathTimeout(sockPath, 80)
}

// restartSocketAttempts is the poll count used after a `systemctl restart`. A
// systemd service takes longer to come back than a direct launch (unit activation,
// daemon initialisation), so the restart path is given 20 seconds rather than the
// 8 seconds waitForSocketPath uses. Short enough not to hang a command, long enough
// that a normally-starting daemon is not misreported as failed.
const restartSocketAttempts = 200 // 200 x 100ms = 20s

// waitForSocketPathTimeout polls for a specific socket file/named pipe to appear
// and be dialable, for attempts polls at 100ms intervals.
func waitForSocketPathTimeout(sockPath string, attempts int) error {
	for i := 0; i < attempts; i++ {
		c, err := dialCLOEXEC(sockPath)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("keychain-auth daemon started but socket/pipe at %s not available after %d seconds", sockPath, attempts/10)
}

// waitForSocket polls for the default socket file/named pipe to appear and be dialable.
func waitForSocket() error {
	return waitForSocketPath(SocketPath())
}

// computeHash returns the SHA-256 hash of a file in "sha256:<hex>" format.
func computeHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
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
	// Bounded: this runs on the startup path of ordinary commands, and a wedged
	// binary must not hang the CLI.
	out, err := runProbe(binPath, "--version")
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
		if v2 == "dev" || v2 == "vdev" {
			return 0
		}
		return -1
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
	if _, err := os.Stat("/etc/keychain-auth/config.json"); err == nil {
		return nil
	}

	// Run install command via sudo (non-interactive — the caller cached the
	// credential; a fresh install prompts once before this point).
	output, err := runSudo(180*time.Second, keychainAuthPath, "install")
	if err != nil {
		return fmt.Errorf("keychain-auth system installer command failed: %w\nOutput: %s", err, string(output))
	}

	ensureStoreReadableByDaemon("/etc/keychain-auth/config.json")
	return nil
}

// ensureStoreReadableByDaemon makes the trust store readable by the daemon that
// must load it, without exposing it to every user on the machine.
//
// The system installer can leave the store root-owned and mode 0600, which the
// daemon — running as its own unprivileged system user — then cannot read, failing
// with "read config file: permission denied". The fix is group ownership, not world
// readability: chown to the daemon's group and use 0640. Only if that is not
// possible do we fall back to 0644, which keeps setup working on systems where the
// daemon user cannot be determined (the store holds no secrets, just the list of
// trusted binary paths and hashes).
func ensureStoreReadableByDaemon(storePath string) {
	for _, group := range []string{"keychain-auth", "keychainauth"} {
		if _, err := user.LookupGroup(group); err != nil {
			continue
		}
		if _, err := runSudo(20*time.Second, "chown", "root:"+group, storePath); err != nil {
			continue
		}
		if _, err := runSudo(20*time.Second, "chmod", "640", storePath); err == nil {
			return
		}
	}
	// Fallback: preserve working setup on hosts where the daemon group is unknown.
	_, _ = runSudo(20*time.Second, "chmod", "644", storePath)
}
