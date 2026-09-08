package commands

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keychainauth"
	"github.com/The-17/agentsecrets/pkg/telemetry"
	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

// Version is set at build time via ldflags
var Version = "3.2.3"

// rootCmd is the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "agentsecrets",
	Short: "Secure secrets management for the AI era",
	Long: lipgloss.JoinVertical(lipgloss.Left,
		"",
		ui.BrandStyle.Render("AgentSecrets"),
		ui.DimStyle.Render("   Zero-knowledge secrets manager for AI-assisted development"),
		"",
		ui.LabelStyle.Render("   Manage secrets across projects, teams, and environments."),
		ui.LabelStyle.Render("   AI assistants can use this tool without seeing secret values."),
		"",
		ui.DimStyle.Render("   Get started:"),
		"   "+ui.BrandStyle.Render("agentsecrets init")+"        "+ui.LabelStyle.Render("Create a new account"),
		"   "+ui.BrandStyle.Render("agentsecrets login")+"       "+ui.LabelStyle.Render("Login to existing account"),
		"   "+ui.BrandStyle.Render("agentsecrets status")+"      "+ui.LabelStyle.Render("Show current session info"),
		"",
	),
	Version:       Version,
	SilenceErrors: true,
	SilenceUsage:  true,
}

func Execute() error {
	ui.CLIVersion = Version
	// Wire dynamic server URL resolution
	api.ResolveBaseURLFunc = config.GetServerURL

	// Ensure keychain-auth socket is closed on exit
	defer keychainauth.Close()

	// Register verb-noun and singular/plural command aliases. Done here (not in
	// an init) so every command's flags and subcommands are already registered,
	// independent of Go's per-file init() ordering.
	registerAliases()

	// Register telemetry callbacks to avoid import cycles
	telemetry.KeychainInitializedFunc = keychainauth.IsInitialized
	telemetry.LoadProjectIDFunc = func() string {
		if project, err := config.LoadProjectConfig(); err == nil && project != nil {
			return project.ProjectID
		}
		return ""
	}
	telemetry.LoadGlobalConfigFunc = func() (string, string, string) {
		if gc, err := config.LoadGlobalConfig(); err == nil && gc != nil {
			wsType := "personal"
			if gc.SelectedWorkspaceID != "" {
				if ws, ok := gc.Workspaces[gc.SelectedWorkspaceID]; ok {
					if ws.Type != "" {
						wsType = ws.Type
					}
				}
			}
			return gc.SelectedWorkspaceID, gc.Email, wsType
		}
		return "", "", "personal"
	}
	telemetry.ResolveEnvironmentFunc = config.ResolveEnvironment

	// Machine-facing and metadata-only invocations (--version, --help, shell
	// completion, `mcp serve`, `exec`) skip the interactive preamble: no update
	// banner, no per-command telemetry record, and no telemetry sync. These run
	// on hot or non-interactive paths where a network round-trip and a stdout
	// banner are unwanted.
	if !skipPreamble() {
		// Run update check. It's efficient (24h interval) and has a short timeout.
		if res, _ := config.CheckForUpdates(Version); res != nil && res.NewVersionAvailable {
			ui.Banner(fmt.Sprintf("Update Available: %s → %s", res.CurrentVersion, res.LatestVersion))
			ui.Info("Run 'brew upgrade agentsecrets', 'npm install -g @the-17/agentsecrets',")
			ui.Info("or 'pip install agentsecrets-cli' to update.")
			ui.Divider()
			fmt.Println()
		}

		// Record telemetry for the executed command
		cmdName := "root"
		if len(os.Args) > 1 {
			cmdName = os.Args[1]
		}
		telemetry.RecordCommand(cmdName)

		// Sync telemetry in background if 24 hours have passed. Deferred so it runs
		// after the command completes — including on the error paths below, which
		// now return rather than os.Exit, letting this and keychainauth.Close run.
		// app.API() constructs the service graph lazily; a metadata-only path that
		// skipped the preamble never built the API client, so this path doesn't
		// force construction either.
		defer telemetry.SyncIfDue(app.API(), Version)
	}

	if err := rootCmd.Execute(); err != nil {
		// A command may return an ExitError to request a specific exit code
		// (e.g. env propagating a child's code, or exec's machine protocol).
		// Silent ExitErrors have already written their own message, so don't
		// double-render. Returning the error — instead of os.Exit here — lets the
		// deferred cleanup above run before main.go performs the actual exit.
		var ee *ExitError
		if errors.As(err, &ee) {
			if !ee.Silent {
				ui.ErrorWithSuggestions(err)
			}
			return err
		}
		ui.ErrorWithSuggestions(err)
		return err
	}
	return nil
}

// skipPreamble reports whether the current invocation should bypass the update
// check and telemetry preamble. It matches metadata flags (--version/-v/--help/-h),
// the help subcommand, shell completion, the MCP server, and the exec provider —
// all non-interactive or latency-sensitive paths.
func skipPreamble() bool {
	if len(os.Args) < 2 {
		return false
	}
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-v" || arg == "--help" || arg == "-h" {
			return true
		}
	}
	switch os.Args[1] {
	case "help", "completion", "mcp", "exec":
		return true
	}
	return false
}

func init() {
	// Register all subcommands
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(statusCmd)

	// Add auth middleware to commands that require it
	workspaceCmd.PersistentPreRunE = keychainAuthMiddleware
	projectCmd.PersistentPreRunE = keychainAuthMiddleware
	environmentCmd.PersistentPreRunE = keychainAuthMiddleware
	agentCmd.PersistentPreRunE = keychainAuthMiddleware

	// Commands that read secrets or display sensitive info need auth verification.
	// The keychainAuthMiddleware handles this.
	secretsCmd.PersistentPreRunE = keychainAuthMiddleware
	callCmd.PersistentPreRunE = keychainAuthMiddleware

	statusCmd.PersistentPreRunE = daemonOnlyMiddleware
	loginCmd.PersistentPreRunE = daemonOnlyMiddleware
	initCmd.PersistentPreRunE = daemonOnlyMiddleware

	rootCmd.AddCommand(workspaceCmd)
	rootCmd.AddCommand(projectCmd)
	rootCmd.AddCommand(secretsCmd)
	rootCmd.AddCommand(agentCmd)
	rootCmd.AddCommand(logsCmd)
	rootCmd.AddCommand(proxyCmd)
	rootCmd.AddCommand(mcpCmd)
	rootCmd.AddCommand(callCmd)
	rootCmd.AddCommand(environmentCmd)
	rootCmd.AddCommand(NewEnvCmd())
	rootCmd.AddCommand(NewExecCmd())
	rootCmd.AddCommand(docsCmd)
}

// ensureSudoCached makes sure a sudo credential is cached before a spinner
// starts, so the password prompt isn't hidden behind spinner output. On Linux,
// if `sudo -n true` fails (no cached credential), it prints reason and runs
// `sudo -v` interactively. No-op on non-Linux platforms.
func ensureSudoCached(reason string) {
	if runtime.GOOS != "linux" {
		return
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err == nil {
		return // already cached
	}
	fmt.Println(reason)
	sudoVal := exec.Command("sudo", "-v")
	sudoVal.Stdin = os.Stdin
	sudoVal.Stdout = os.Stdout
	sudoVal.Stderr = os.Stderr
	_ = sudoVal.Run() // wait for password entry to cache it
}

// keychainRequiredError prints the manual-setup hint and returns the canonical
// "keychain-auth is required" error, used whenever a transparent recovery fails.
func keychainRequiredError(action string, cause error) error {
	ui.Error(action + " failed: " + cause.Error())
	fmt.Println()
	ui.Info("You can set it up manually:")
	ui.Info("  brew install The-17/tap/keychain-auth")
	ui.Info("  keychain-auth start")
	fmt.Println()
	return fmt.Errorf("keychain-auth is required for secure credentials storage")
}

// recoveryKind classifies an Init() failure into the transparent-recovery
// action that can fix it, decoupling recovery from brittle substring matching.
type recoveryKind int

const (
	recoverNone       recoveryKind = iota // unrecoverable — surface to the user
	recoverDaemon                         // daemon missing/not running — clean socket + (re)start
	recoverProtocol                       // protocol/version mismatch — restart daemon in place
	recoverRegister                       // binary unregistered/hash-changed/conn dropped — re-register + restart
)

// classifyInitError maps an Init() error to the recovery action that applies.
// Typed errors (DaemonNotRunningError, DaemonDeniedError) are preferred; a small
// set of connection-drop substrings is retained only where the daemon reports
// the condition without a typed error.
func classifyInitError(err error) recoveryKind {
	if err == nil {
		return recoverNone
	}

	var notRunning *keychainauth.DaemonNotRunningError
	if errors.As(err, &notRunning) {
		return recoverDaemon
	}

	errStr := err.Error()
	if strings.Contains(errStr, "protocol mismatch") || strings.Contains(errStr, "unexpected response status") {
		return recoverProtocol
	}

	var denied *keychainauth.DaemonDeniedError
	if errors.As(err, &denied) && (denied.IsUnregistered() || denied.IsHashMismatch()) {
		return recoverRegister
	}
	if strings.Contains(errStr, "daemon closed connection immediately") ||
		strings.Contains(errStr, "connection closed by daemon") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer") {
		return recoverRegister
	}

	return recoverNone
}

// recoverDaemonState performs the transparent recovery for a given kind and
// returns the result of a fresh Init(). Each kind caches sudo, runs its repair
// under a spinner, then re-initializes the connection.
func recoverDaemonState(kind recoveryKind) error {
	switch kind {
	case recoverDaemon:
		keychainauth.Close()
		_ = os.Remove(keychainauth.SocketPath())
		ensureSudoCached("keychain-auth daemon restart is required. Please authorize when prompted.")
		if err := ui.Spinner("Starting keychain-auth daemon...", keychainauth.AutoSetup); err != nil {
			return keychainRequiredError("keychain-auth setup", err)
		}
		return keychainauth.Init()

	case recoverProtocol:
		keychainauth.Close()
		ensureSudoCached("keychain-auth daemon restart is required. Please authorize when prompted.")
		if err := ui.Spinner("Starting keychain-auth daemon...", keychainauth.RestartDaemon); err != nil {
			return keychainRequiredError("keychain-auth setup", err)
		}
		return keychainauth.Init()

	case recoverRegister:
		keychainauth.Close()
		ensureSudoCached("keychain-auth binary registration is required. Please authorize when prompted.")
		if err := ui.Spinner("Registering agentsecrets binary with daemon...", func() error {
			kcPath, err := keychainauth.EnsureInstalled()
			if err != nil {
				return err
			}
			if err := keychainauth.EnsureRegistered(kcPath); err != nil {
				return err
			}
			return keychainauth.RestartDaemon()
		}); err != nil {
			return keychainRequiredError("keychain-auth registration", err)
		}
		return keychainauth.Init()

	default:
		return nil
	}
}

// ensureDaemonInitialized ensures that:
// 1. The keychain-auth daemon is set up and running (AutoSetup if missing/outdated)
// 2. The client is successfully initialized and connected to the daemon socket/named pipe
// 3. Our binary is still accepted (registered) by the daemon — checked only when
//    the binary changed since it was last accepted (e.g. right after an upgrade).
//
// Recovery is a bounded loop: each failure is classified into a typed recoveryKind,
// the matching repair runs at most once per kind, and the attempt is retried. A
// persistently failing daemon surfaces its UserMessage instead of looping forever.
func ensureDaemonInitialized() error {
	// Step 1: Skip if connection already established
	if keychainauth.IsInitialized() {
		return nil
	}

	// Step 2: If daemon is not running, try starting it. If not installed, run auto-setup.
	if !keychainauth.IsAvailable() {
		if kcPath, err := keychainauth.EnsureInstalled(); err == nil {
			_ = keychainauth.EnsureDaemonRunning(kcPath)
		}
		if !keychainauth.IsAvailable() {
			ensureSudoCached("keychain-auth sandbox system setup is required. Please authorize when prompted.")
			if err := ui.Spinner("Setting up keychain-auth...", keychainauth.AutoSetup); err != nil {
				return keychainRequiredError("keychain-auth setup", err)
			}
		}
	}

	// Step 3: When our binary changed since it was last accepted (e.g. right after
	// an agentsecrets upgrade), this is also when a co-released daemon upgrade is
	// due — RequiredDaemonVersion is baked into this binary. Bring the daemon up to
	// the required version first, before connecting, so we Init against the new
	// daemon rather than connecting to the old one and then restarting it out from
	// under ourselves. Gated by the same local marker as Step 5, so an unchanged
	// binary skips this entirely and adds no per-command latency.
	binaryChanged := binaryVerificationNeeded()
	if binaryChanged && keychainauth.DaemonUpdateNeeded() {
		ensureSudoCached("A keychain-auth daemon update is required. Please authorize when prompted.")
		if err := ui.Spinner("Updating keychain-auth daemon...", keychainauth.EnsureDaemonUpToDate); err != nil {
			return keychainRequiredError("keychain-auth update", err)
		}
	}

	// Step 4: Establish the connection, recovering from typed failures.
	if err := recoverableAttempt(keychainauth.Init); err != nil {
		return fmt.Errorf("%s", keychainauth.UserMessage(err))
	}

	// Step 5: Verify our binary is still registered — but only when warranted.
	// The daemon persists this binary's registration across runs, so the check is
	// only needed the first time we run a *changed* binary (e.g. right after an
	// upgrade), when the hash the daemon recorded no longer matches ours. Init
	// stays probe-free, so an unregistered binary would otherwise sail through
	// Init and only get denied on the first real request — bypassing recovery. We
	// record the last-accepted binary signature locally; while it's unchanged we
	// skip this round-trip entirely (no per-command latency), and when it differs
	// we verify once and let the recovery ladder re-register transparently.
	if binaryChanged {
		if err := recoverableAttempt(keychainauth.Verify); err != nil {
			return fmt.Errorf("%s", keychainauth.UserMessage(err))
		}
		recordBinaryVerified()
	}
	return nil
}

// recoverableAttempt runs attempt(), and on failure classifies the error into a
// typed recoveryKind, performs the matching repair, and retries — at most once
// per distinct kind so a persistently failing daemon surfaces its message instead
// of looping. recoverDaemonState re-establishes the connection, after which the
// original attempt is retried against the repaired daemon.
func recoverableAttempt(attempt func() error) error {
	err := attempt()
	tried := map[recoveryKind]bool{}
	for err != nil {
		kind := classifyInitError(err)
		if kind == recoverNone || tried[kind] {
			break
		}
		tried[kind] = true
		if rerr := recoverDaemonState(kind); rerr != nil {
			err = rerr // recovery itself failed — reclassify (usually terminal)
			continue
		}
		err = attempt() // connection repaired; retry the real attempt
	}
	return err
}

// keychainMarkerPath returns the sentinel file that records the last binary
// signature the daemon accepted. Stored under ~/.agentsecrets so it persists
// across runs and upgrades.
func keychainMarkerPath() (string, error) {
	paths, err := config.GetPaths()
	if err != nil {
		return "", err
	}
	return filepath.Join(paths.GlobalDir, "keychain-verified"), nil
}

// binarySignature returns a cheap identity for the running executable: resolved
// path + size + modtime. A binary upgrade changes at least the modtime, which is
// all we need to decide whether to re-verify. It is a change *hint*, not a
// security check — the daemon still hash-verifies this binary on every real
// request. An empty string (couldn't stat self) forces verification.
func binarySignature() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, rerr := filepath.EvalSymlinks(path); rerr == nil {
		path = resolved
	}
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s|%d|%d", path, info.Size(), info.ModTime().UnixNano())
}

// binaryVerificationNeeded reports whether to issue a daemon verification request
// before proceeding. True when the marker is missing or the running binary's
// signature differs from the last accepted one (e.g. after an upgrade).
func binaryVerificationNeeded() bool {
	sig := binarySignature()
	if sig == "" {
		return true
	}
	markerPath, err := keychainMarkerPath()
	if err != nil {
		return true
	}
	data, err := os.ReadFile(markerPath)
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(data)) != sig
}

// recordBinaryVerified persists the running binary's signature so subsequent runs
// of the same binary skip the verification round-trip. Best-effort: a write
// failure just means we verify again next time.
func recordBinaryVerified() {
	sig := binarySignature()
	if sig == "" {
		return
	}
	markerPath, err := keychainMarkerPath()
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(markerPath), 0700)
	_ = os.WriteFile(markerPath, []byte(sig), 0600)
}

// keychainAuthMiddleware is a PersistentPreRunE that ensures both:
// 1. The keychain-auth connection is established
// 2. The user is authenticated (EnsureAuth)
func keychainAuthMiddleware(cmd *cobra.Command, args []string) error {
	if err := ensureDaemonInitialized(); err != nil {
		return err
	}
	return app.Auth().EnsureAuth(cmd, args)
}

// daemonOnlyMiddleware is a PersistentPreRunE that ensures the keychain-auth daemon
// connection is established (without requiring user authentication first).
// Used by bootstrap/login/logout flow.
func daemonOnlyMiddleware(cmd *cobra.Command, args []string) error {
	return ensureDaemonInitialized()
}

// currentProjectID resolves the active project ID from the local project config,
// falling back to the globally selected project ID when no project is bound in
// the current directory (or the config cannot be loaded).
func currentProjectID() string {
	pc, err := config.LoadProjectConfig()
	if err == nil && pc != nil && pc.ProjectID != "" {
		return pc.ProjectID
	}
	return config.GetSelectedProjectID()
}
