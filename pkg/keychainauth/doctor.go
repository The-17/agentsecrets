package keychainauth

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// This file implements the reconciler behind `agentsecrets doctor` and the
// transparent recovery inside normal commands. Both share these checks so the
// doctor's idea of "healthy" can't drift from what recovery actually repairs.
//
// Every check probes real state (stat, exec, socket dial) and every repair is
// idempotent, so running the doctor twice is always safe.
//
// The invariants a working installation satisfies:
//
//	I1  a keychain-auth binary exists at >= RequiredDaemonVersion
//	I2  the daemon is running and its socket/pipe is dialable
//	I3  the running daemon isn't older than the binary on disk
//	I4  this exact agentsecrets binary (path + SHA-256) is in the daemon's store
//	I5  the daemon *in memory* accepts us — a live request is granted
//	I6  no stale socket files shadow a dead daemon
//	I7  the trust store isn't writable by unprivileged users
//	I8  stored credentials are readable

// Status is the outcome of a single check.
type Status int

const (
	StatusOK      Status = iota // invariant holds
	StatusWarn                  // degraded but functional
	StatusBroken                // invariant violated; secrets access will fail
	StatusSkipped               // not applicable on this platform / not determinable
)

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusWarn:
		return "warn"
	case StatusBroken:
		return "broken"
	default:
		return "skipped"
	}
}

// Finding is one check's verdict. A non-nil repair means the doctor can fix it
// without user intervention; otherwise Remedy carries actionable guidance.
type Finding struct {
	ID     string
	Title  string
	Detail string
	Status Status
	Remedy string

	repair    func() error
	needsSudo bool
}

// Fixable reports whether this finding has an automatic repair.
func (f Finding) Fixable() bool { return f.repair != nil }

// NeedsSudo reports whether repairing this finding will prompt for elevation.
func (f Finding) NeedsSudo() bool { return f.needsSudo }

// Platform captures the host facts that change which checks apply and which
// repairs are possible.
type Platform struct {
	OS string // runtime.GOOS

	// IsWSL and HasSystemd decide how the daemon can be supervised on Linux. WSL
	// distros frequently ship without systemd, in which case the only working
	// arrangement is a user-mode daemon — worth stating plainly in diagnostics
	// rather than leaving the user to wonder why there is no service.
	IsWSL      bool
	HasSystemd bool

	// CanSudo gates repairs that need elevation. Without sudo we must not offer to
	// fix a system-mode installation, only explain what is needed.
	CanSudo bool
}

// DetectPlatform probes the host environment.
func DetectPlatform() Platform {
	p := Platform{OS: runtime.GOOS}

	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/version"); err == nil {
			v := strings.ToLower(string(data))
			p.IsWSL = strings.Contains(v, "microsoft") || strings.Contains(v, "wsl")
		}
		if os.Getenv("WSL_DISTRO_NAME") != "" {
			p.IsWSL = true
		}
		// systemd is only usable as a service manager when its runtime dir exists.
		if st, err := os.Stat("/run/systemd/system"); err == nil && st.IsDir() {
			p.HasSystemd = true
		}
	}

	if runtime.GOOS != "windows" {
		if _, err := exec.LookPath("sudo"); err == nil {
			p.CanSudo = true
		}
	}
	return p
}

// Report is the result of a full diagnosis, plus the probe context the repairs need.
type Report struct {
	Platform Platform
	Findings []Finding

	// Probe context, exposed for rendering.
	KeychainAuthPath string
	DaemonVersion    string
	DaemonMode       string
	SocketPath       string
	ConfigPath       string
	SelfPath         string
	SelfHash         string

	info *DaemonInfo
	reg  *registrationState
}

// Healthy reports whether every applicable invariant holds (warnings allowed).
func (r *Report) Healthy() bool {
	for _, f := range r.Findings {
		if f.Status == StatusBroken {
			return false
		}
	}
	return true
}

// Broken returns the findings that violate an invariant.
func (r *Report) Broken() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Status == StatusBroken {
			out = append(out, f)
		}
	}
	return out
}

// NeedsSudo reports whether repairing the broken findings will require elevation,
// letting the caller cache a sudo credential once instead of prompting mid-spinner.
func (r *Report) NeedsSudo() bool {
	for _, f := range r.Findings {
		if f.Status == StatusBroken && f.Fixable() && f.needsSudo {
			return true
		}
	}
	return false
}

func (r *Report) add(f Finding) {
	// A repair that needs elevation is not actually available without sudo. Turn it
	// into guidance rather than offering a fix that is guaranteed to fail.
	if f.repair != nil && f.needsSudo && r.Platform.OS != "windows" && !r.Platform.CanSudo {
		f.repair = nil
		if f.Remedy == "" {
			f.Remedy = "This repair needs administrator rights, but sudo is not available. " +
				"Re-run as root, or install keychain-auth in user mode."
		}
	}
	r.Findings = append(r.Findings, f)
}

// checkServiceManager explains how the daemon is supervised on Linux. On WSL and
// other systemd-less environments there is deliberately no system service — the
// daemon runs in user mode — and saying so prevents users from chasing a
// `systemctl` unit that was never meant to exist.
func (r *Report) checkServiceManager() {
	if r.Platform.OS != "linux" {
		return
	}
	if r.Platform.HasSystemd {
		return
	}
	detail := "systemd is not available on this host, so keychain-auth runs as a user-mode background process"
	if r.Platform.IsWSL {
		detail = "this WSL distro has no systemd, so keychain-auth runs as a user-mode background process"
	}
	r.add(Finding{
		ID:     "service.user-mode",
		Title:  "Daemon is supervised without systemd",
		Detail: detail + "; it must be restarted when the distro restarts",
		Status: StatusOK,
	})
}

// Diagnose probes the whole local installation and returns a Report.
//
// It is strictly read-only: nothing is installed, started, authorized or modified,
// and it never prompts. Every daemon request it makes bypasses the request-time
// repair path, because during diagnosis a denial is the answer we want to record —
// not a trigger to start fixing things behind the user's back.
func Diagnose() *Report {
	r := &Report{Platform: DetectPlatform()}

	// --- I1: a keychain-auth binary of a sufficient version exists -------------
	r.KeychainAuthPath = findBestDaemon()
	if r.KeychainAuthPath == "" {
		r.add(Finding{
			ID:        "daemon.missing",
			Title:     "keychain-auth is not installed",
			Detail:    "No keychain-auth binary was found in any standard location.",
			Status:    StatusBroken,
			repair:    func() error { _, err := EnsureInstalled(); return err },
			needsSudo: false,
		})
		// Everything downstream depends on the binary; stop here.
		return r
	}

	installedVer, verErr := queryInstalledVersion(r.KeychainAuthPath)
	r.DaemonVersion = installedVer
	switch {
	case verErr != nil:
		r.add(Finding{
			ID:     "daemon.version-unknown",
			Title:  "keychain-auth version could not be determined",
			Detail: fmt.Sprintf("%s did not report a version: %v", r.KeychainAuthPath, verErr),
			Status: StatusWarn,
			repair: func() error { _, err := EnsureInstalled(); return err },
		})
	case compareVersions(installedVer, RequiredDaemonVersion) < 0:
		r.add(Finding{
			ID:     "daemon.outdated",
			Title:  "keychain-auth is older than this AgentSecrets build requires",
			Detail: fmt.Sprintf("found %s at %s, need >= %s", installedVer, r.KeychainAuthPath, RequiredDaemonVersion),
			Status: StatusBroken,
			// Upgrading the system copy and restarting the service needs elevation.
			needsSudo: r.Platform.OS == "linux",
			repair:    EnsureDaemonUpToDate,
		})
	default:
		r.add(Finding{
			ID:     "daemon.installed",
			Title:  "keychain-auth installed",
			Detail: fmt.Sprintf("%s (%s)", installedVer, r.KeychainAuthPath),
			Status: StatusOK,
		})
	}

	// Ask the daemon how it is configured rather than inferring from socket paths.
	if info, err := QueryDaemonInfo(r.KeychainAuthPath); err == nil {
		r.info = info
		r.DaemonMode = info.Mode
		r.SocketPath = info.SocketPath
		r.ConfigPath = info.ConfigPath
	} else {
		r.SocketPath = SocketPath()
		r.add(Finding{
			ID:     "daemon.status-unavailable",
			Title:  "keychain-auth could not report its own status",
			Detail: fmt.Sprintf("`%s status --json` failed: %v", filepath.Base(r.KeychainAuthPath), err),
			Status: StatusWarn,
			Remedy: "This usually means an outdated daemon. Upgrading keychain-auth resolves it.",
			repair: EnsureDaemonUpToDate,
		})
	}

	// --- I2: the daemon is running and its socket is dialable ------------------
	socketLive := IsAvailable()
	if socketLive {
		r.add(Finding{
			ID:     "daemon.running",
			Title:  "keychain-auth daemon is running",
			Detail: fmt.Sprintf("socket %s is accepting connections", SocketPath()),
			Status: StatusOK,
		})
	} else {
		r.add(Finding{
			ID:        "daemon.not-running",
			Title:     "keychain-auth daemon is not running",
			Detail:    fmt.Sprintf("nothing is listening on %s", r.SocketPath),
			Status:    StatusBroken,
			needsSudo: r.Platform.OS == "linux" && r.daemonNeedsSudo(),
			repair:    AutoSetup,
		})
	}

	// --- I6: stale socket files shadowing a dead daemon -----------------------
	// A leftover socket file makes clients believe a daemon exists and produces
	// confusing "connection refused" instead of "not running".
	if runtime.GOOS != "windows" && !socketLive {
		for _, sp := range uniqueStrings(SocketPath(), UserSocketPath(), r.SocketPath) {
			if sp == "" {
				continue
			}
			if _, err := os.Stat(sp); err == nil {
				sp := sp
				r.add(Finding{
					ID:     "socket.stale",
					Title:  "Stale socket file from a dead daemon",
					Detail: sp + " exists but nothing is listening",
					Status: StatusWarn,
					repair: func() error {
						if err := os.Remove(sp); err != nil && !os.IsNotExist(err) {
							return err
						}
						return nil
					},
				})
			}
		}
	}

	// --- I3: the running daemon is not older than the binary on disk ----------
	// brew/download replaces the file, but the already-running process keeps
	// serving old code until restarted.
	if running := runningDaemonBinary(); running != "" && socketLive {
		if runningVer, err := queryInstalledVersion(running); err == nil {
			if compareVersions(runningVer, RequiredDaemonVersion) < 0 {
				r.add(Finding{
					ID:    "daemon.stale-process",
					Title: "A stale keychain-auth process is serving old code",
					Detail: fmt.Sprintf("running %s (%s) but %s is required; the on-disk binary was upgraded without restarting the daemon",
						runningVer, running, RequiredDaemonVersion),
					Status:    StatusBroken,
					needsSudo: r.Platform.OS == "linux" && r.daemonNeedsSudo(),
					repair:    EnsureDaemonUpToDate,
				})
			}
		}
	}

	// --- I4 / I5: this binary is registered, and the daemon actually accepts it
	r.checkRegistrationInvariants(socketLive)

	// Platform-specific context: how the daemon is supervised.
	r.checkServiceManager()

	// --- I7: the trust store must not be writable by unprivileged users -------
	r.checkStorePermissions()

	// --- I8: credentials are readable and agree with local session state ------
	r.checkCredentials(socketLive)

	return r
}

// daemonNeedsSudo reports whether daemon lifecycle operations require elevation,
// preferring the daemon's own answer over a socket-path guess.
func (r *Report) daemonNeedsSudo() bool {
	if r.info != nil {
		return r.info.RequiresSudo
	}
	return requiresSudoForRegistration(r.KeychainAuthPath)
}

// checkRegistrationInvariants verifies I4 (our path+hash is in the daemon's trust
// store) and I5 (the daemon's in-memory policy actually grants us access).
//
// I5 is the check that catches the failure users hit most: authorizing a binary
// writes the trust store, but a daemon that was already running keeps its old
// policy in memory and keeps denying an "unregistered" binary that the store now
// approves. Only a live request can detect that, so we issue one.
func (r *Report) checkRegistrationInvariants(socketLive bool) {
	configPath := r.ConfigPath
	if configPath == "" && r.info != nil {
		configPath = r.info.ConfigPath
	}

	reg, err := inspectRegistration(configPath)
	if err != nil {
		r.add(Finding{
			ID:     "registration.unknown",
			Title:  "Could not determine this binary's identity",
			Detail: err.Error(),
			Status: StatusWarn,
		})
		return
	}
	r.reg = reg
	r.SelfPath = reg.SelfPath
	r.SelfHash = reg.SelfHash

	// The daemon's own verdict works even when its store is unreadable by us.
	registered, detail := checkRegistered(r.KeychainAuthPath, reg.SelfPath)

	switch {
	case registered:
		r.add(Finding{
			ID:     "registration.present",
			Title:  "This AgentSecrets binary is authorized",
			Detail: fmt.Sprintf("%s is registered for the %s namespace", reg.SelfPath, serviceName),
			Status: StatusOK,
		})
	case reg.PathFound && !reg.HashMatches:
		r.add(Finding{
			ID:    "registration.hash-mismatch",
			Title: "This AgentSecrets binary changed since it was authorized",
			Detail: fmt.Sprintf("%s was upgraded; the daemon recorded a different hash (expected %s, have %s)",
				reg.SelfPath, shortHash(reg.StoreHash), shortHash(reg.SelfHash)),
			Status:    StatusBroken,
			needsSudo: r.daemonNeedsSudo(),
			repair:    RegisterAndActivate,
		})
	default:
		d := "this binary is not in the keychain-auth trust store"
		if detail != "" {
			d = detail
		}
		if reg.StoreReadErr != nil {
			d += " (trust store not readable by this user, which is expected)"
		}
		r.add(Finding{
			ID:        "registration.missing",
			Title:     "This AgentSecrets binary is not yet authorized",
			Detail:    fmt.Sprintf("%s: %s", reg.SelfPath, d),
			Status:    StatusBroken,
			needsSudo: r.daemonNeedsSudo(),
			repair:    RegisterAndActivate,
		})
	}

	// I5 — only meaningful while a daemon is up to answer.
	if !socketLive {
		r.add(Finding{
			ID:     "policy.effective",
			Title:  "Daemon policy could not be verified",
			Detail: "the daemon is not running, so no live request could be made",
			Status: StatusSkipped,
		})
		return
	}

	if err := probeDaemonGrant(); err != nil {
		var denied *DaemonDeniedError
		if errors.As(err, &denied) && (denied.IsUnregistered() || denied.IsHashMismatch()) {
			r.add(Finding{
				ID:    "policy.stale",
				Title: "The running daemon is not granting this binary access",
				Detail: "a live request was denied. This happens when the daemon's in-memory policy predates the " +
					"authorization (it must be restarted to reload), or when this binary was never authorized at all",
				Status:    StatusBroken,
				needsSudo: r.daemonNeedsSudo(),
				repair:    RegisterAndActivate,
			})
			return
		}
		r.add(Finding{
			ID:     "policy.unverified",
			Title:  "Daemon did not answer a verification request",
			Detail: err.Error(),
			Status: StatusWarn,
			repair: RegisterAndActivate,
		})
		return
	}

	r.add(Finding{
		ID:     "policy.effective",
		Title:  "Daemon grants this binary access",
		Detail: "a live verification request was accepted",
		Status: StatusOK,
	})
}

// checkStorePermissions verifies I7. The trust store decides which binaries may
// read secrets, so unprivileged write access to it is a privilege-escalation path.
// World-readability is reported separately: it discloses which binaries are trusted
// without granting anything, so it is a warning rather than a breakage, and it is
// never "repaired" by loosening permissions.
func (r *Report) checkStorePermissions() {
	if runtime.GOOS == "windows" || r.ConfigPath == "" {
		return
	}
	st, err := os.Stat(r.ConfigPath)
	if err != nil {
		return // absent store is covered by the registration checks
	}
	mode := st.Mode().Perm()

	if mode&0o022 != 0 {
		path := r.ConfigPath
		r.add(Finding{
			ID:     "store.writable",
			Title:  "keychain-auth trust store is writable by other users",
			Detail: fmt.Sprintf("%s has mode %#o; group/other write allows tampering with which binaries are trusted", path, mode),
			Status: StatusBroken,
			// Tightening permissions is a security fix, so it is safe to automate.
			needsSudo: r.daemonNeedsSudo(),
			repair: func() error {
				return tightenStorePermissions(path, mode)
			},
		})
		return
	}

	if mode&0o004 != 0 {
		r.add(Finding{
			ID:     "store.world-readable",
			Title:  "keychain-auth trust store is world-readable",
			Detail: fmt.Sprintf("%s has mode %#o; it reveals which binaries are trusted", r.ConfigPath, mode),
			Status: StatusWarn,
			Remedy: "Not exploitable on its own — the store holds no secrets and the daemon still verifies hashes. " +
				"Tighten it only if your threat model requires hiding the trusted-binary list.",
		})
		return
	}

	r.add(Finding{
		ID:     "store.permissions",
		Title:  "keychain-auth trust store permissions are sound",
		Detail: fmt.Sprintf("%s has mode %#o", r.ConfigPath, mode),
		Status: StatusOK,
	})
}

// checkCredentials verifies I8: that credentials stored behind the daemon are
// actually readable. A mode switch (system <-> user daemon) moves the underlying
// store, which silently orphans previously-saved tokens — the user appears logged
// out, or logged in with no usable workspace keys. Detecting it here turns a
// baffling "workspace key not found" into a clear "log in again".
func (r *Report) checkCredentials(socketLive bool) {
	if !socketLive {
		r.add(Finding{
			ID:     "credentials.unknown",
			Title:  "Stored credentials could not be checked",
			Detail: "the daemon is not running",
			Status: StatusSkipped,
		})
		return
	}

	// Read the token entry directly, bypassing the repairing wrapper: diagnosis
	// must not authorize anything or prompt for elevation.
	resp, err := sendRequestOnce(request{
		Type:    typeRequest,
		Action:  actionRead,
		Service: serviceName,
		Targets: []string{"user_tokens"},
	})
	if err == nil && len(resp.Results) > 0 && resp.Results[0].Value != "" {
		r.add(Finding{
			ID:     "credentials.readable",
			Title:  "Stored credentials are readable",
			Detail: "session tokens were retrieved from the keychain",
			Status: StatusOK,
		})
		return
	}

	var denied *DaemonDeniedError
	if errors.As(err, &denied) && (denied.IsUnregistered() || denied.IsHashMismatch()) {
		// Already reported by the registration/policy checks; don't double-report.
		return
	}

	// No tokens is a normal state for a fresh install, so this is not a breakage —
	// it is the signal that a login is needed.
	r.add(Finding{
		ID:     "credentials.absent",
		Title:  "No stored session credentials",
		Detail: "the keychain holds no session tokens for AgentSecrets",
		Status: StatusWarn,
		Remedy: "Run 'agentsecrets login' to sign in. If you were previously logged in, the daemon's " +
			"storage mode changed and the old credentials are no longer reachable — logging in again restores them.",
	})
}

// Repair applies every automatic repair for broken findings, then re-diagnoses to
// prove the result. run, when non-nil, executes each step and lets the caller show
// progress (e.g. a spinner). Repairs are idempotent.
func (r *Report) Repair(run func(label string, fn func() error) error) *Report {
	applied := map[string]bool{}

	for _, f := range r.Findings {
		if f.Status != StatusBroken && f.Status != StatusWarn {
			continue
		}
		if !f.Fixable() || applied[f.ID] {
			continue
		}
		if f.Status == StatusWarn && !isSafeWarnRepair(f.ID) {
			continue
		}
		applied[f.ID] = true
		if run != nil {
			_ = run(f.Title, f.repair)
		} else {
			_ = f.repair()
		}
	}

	// Drop any connection built against the pre-repair daemon before re-probing.
	Close()
	return Diagnose()
}

// isSafeWarnRepair lists warning-level findings whose repair is non-destructive and
// worth doing automatically (as opposed to warnings that are purely informational).
func isSafeWarnRepair(id string) bool {
	switch id {
	case "socket.stale", "daemon.outdated", "daemon.version-unknown", "daemon.status-unavailable", "policy.unverified":
		return true
	}
	return false
}

// tightenStorePermissions removes group/other write bits from the trust store,
// escalating only if the current user cannot do it directly. It never widens
// permissions.
func tightenStorePermissions(path string, current os.FileMode) error {
	target := current &^ os.FileMode(0o022)
	if err := os.Chmod(path, target); err == nil {
		return nil
	}
	if runtime.GOOS == "windows" {
		return fmt.Errorf("cannot tighten permissions on %s", path)
	}
	out, err := runSudo(20*time.Second, "chmod", fmt.Sprintf("%#o", uint32(target)), path)
	if err != nil {
		return fmt.Errorf("tighten %s permissions: %w (%s)", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func shortHash(h string) string {
	h = strings.TrimPrefix(h, "sha256:")
	if len(h) > 12 {
		return h[:12]
	}
	if h == "" {
		return "none"
	}
	return h
}

func uniqueStrings(in ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
