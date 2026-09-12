package commands

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/internal/envguard"
	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keychainauth"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/telemetry"
	"github.com/The-17/agentsecrets/pkg/ui"
)

func NewEnvCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "env [--cloud] [--only KEYS] [--sandbox] -- <command> [args...]",
		Short: "Inject secrets as environment variables into a child process",
		Long: `Resolves secrets and injects them as environment variables into the specified command.
		Supports Dual-Engine resolution:
		- Local Engine (Default): Resolves from local OS keychain (offline, 0ms latency).
		- Cloud Engine: Resolves from AgentSecrets Cloud over TLS via AGENTSECRETS_TOKEN or --cloud.

		The child is made non-dumpable (no other process can read its environment) and
		secret values are redacted from its output.

		--cloud              resolve secrets via AgentSecrets Cloud
		--only KEY[,KEY...]  inject only these secrets (default: all)
		--sandbox            run the child with no network egress (Linux only)`,
		Example: `  agentsecrets env -- npm run dev
  agentsecrets env --cloud -- npm run dev
  agentsecrets env --only DATABASE_URL -- ./run-migrations.sh
  agentsecrets env --sandbox -- ./seed.sh
  AGENTSECRETS_TOKEN=agt_prod_... agentsecrets env -- node server.js`,
		RunE:               runEnv,
		DisableFlagParsing: true,
	}
}

func runEnv(cmd *cobra.Command, args []string) error {
	telemetry.RecordIntegration("env")

	// DisableFlagParsing is active, so leading flags are parsed by hand.
	useCloud := false
	sandbox := false
	var onlyKeys []string
parseArgs:
	for len(args) > 0 {
		switch {
		case args[0] == "--help" || args[0] == "-h":
			return cmd.Help()
		case args[0] == "--cloud":
			useCloud = true
			args = args[1:]
		case args[0] == "--sandbox":
			sandbox = true
			args = args[1:]
		case args[0] == "--only" || strings.HasPrefix(args[0], "--only="):
			val := strings.TrimPrefix(strings.TrimPrefix(args[0], "--only"), "=")
			args = args[1:]
			if val == "" {
				if len(args) == 0 {
					return fmt.Errorf("--only requires a comma-separated list of keys")
				}
				val = args[0]
				args = args[1:]
			}
			onlyKeys = strings.Split(val, ",")
		case args[0] == "--":
			args = args[1:]
			break parseArgs
		default:
			break parseArgs
		}
	}
	if len(args) == 0 {
		return fmt.Errorf("no command specified. Usage: agentsecrets env [--cloud] [--only KEYS] [--sandbox] -- <command> [args...]")
	}

	// Check environment variable triggers for Cloud Mode
	if envVal := strings.ToLower(os.Getenv("AGENTSECRETS_USE_CLOUD")); envVal == "true" || envVal == "1" {
		useCloud = true
	}
	token := os.Getenv("AGENTSECRETS_TOKEN")
	if token != "" {
		useCloud = true
	}

	var secrets map[string]string
	var err error
	var project *config.ProjectConfig

	if useCloud {
		if token == "" {
			return fmt.Errorf("cloud resolution active but AGENTSECRETS_TOKEN is not set. Please provide a valid workload token (agt_...)")
		}

		serverURL := os.Getenv("AGENTSECRETS_SERVER_URL")
		if serverURL == "" {
			serverURL = config.GetServerURL()
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		secrets, err = api.FetchWorkloadEnv(ctx, serverURL, token)
		if err != nil {
			return fmt.Errorf("cloud resolution failed: %w", err)
		}
		ui.Info(fmt.Sprintf("Cloud Engine: Injected %d secrets into process memory", len(secrets)))
	} else {
		// Local Offline Engine Mode
		project, err = config.LoadProjectConfig()
		if err != nil || project == nil || project.ProjectID == "" {
			return fmt.Errorf("no active project. Run: agentsecrets project use <name> (or pass AGENTSECRETS_TOKEN / --cloud for cloud resolution)")
		}

		// Ensure keychain-auth session is established before reading secrets.
		if err := ensureKeychainAuthForEnv(); err != nil {
			return err
		}

		// Resolve all secrets from local OS keychain
		envName := config.ResolveEnvironment()
		secrets, err = keyring.GetAllProjectSecrets(project.ProjectID, envName)
		if err != nil {
			return fmt.Errorf("failed to load secrets from keychain: %w", err)
		}
	}

	// --only narrows what is injected. The default stays "all secrets": a codebase
	// needing thirty credentials should not have to enumerate them.
	if len(onlyKeys) > 0 {
		var missing []string
		secrets, missing = filterSecrets(secrets, onlyKeys)
		if len(missing) > 0 {
			ui.Warning("Not in this project: " + strings.Join(missing, " "))
		}
	}

	if len(secrets) == 0 {
		ui.Warning("No secrets found in active project — running without injection")
	} else if !useCloud {
		secretKeys := make([]string, 0, len(secrets))
		for k := range secrets {
			secretKeys = append(secretKeys, k)
		}
		if len(secretKeys) == 1 {
			ui.Info(fmt.Sprintf("Local Engine: Injecting 1 secret: %s", secretKeys[0]))
		} else {
			ui.Info(fmt.Sprintf("Local Engine: Injecting %d secrets: %s + %d more", len(secretKeys), secretKeys[0], len(secretKeys)-1))
		}
	}

	// Extract candidate target hosts named in the resolved values (URLs, DSNs,
	// host:port strings) before we wrap them into environment variables. Used for
	// the audit log so a reviewer can see where the credentials pointed.
	hosts := hostsFromSecrets(secrets)
	if project != nil {
		if missing := unallowlistedHosts(project.WorkspaceID, hosts); len(missing) > 0 {
			ui.Warning(fmt.Sprintf("%d host(s) in your credentials aren't allowlisted: %s", len(missing), strings.Join(missing, " ")))
			ui.Info("Route them through AgentSecrets: agentsecrets allowlist add " + strings.Join(missing, " "))
		}
	}

	// The preload guard cannot attach to every binary (a statically linked child on
	// Linux, a hardened-runtime child on macOS). Output is still redacted by the
	// parent, but the child's environment protection is reduced. Say so once, and
	// only when a guard is actually installed to attach.
	if envguard.Locate() != "" {
		if target, lerr := exec.LookPath(args[0]); lerr == nil {
			if msg := guardAttachWarning(target); msg != "" {
				ui.Warning(msg)
			}
		}
	}

	// Build environment: parent env + injected secrets
	env := os.Environ()
	for key, value := range secrets {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// Attach the guard interposer: it marks the child non-dumpable (so no other
	// process running as the same user can read its environment) and redacts
	// secret values from its output. Strip any inherited copies of the guard's
	// variables first — duplicates in the environment are ambiguous to the loader.
	env = stripEnv(env, envguard.EnvKeys())
	env = append(env, envguard.PreloadEnv(secrets)...)

	// --sandbox runs the child with no network egress. Opt-in; the default is
	// unchanged.
	argv := args
	if sandbox {
		argv, err = sandboxArgv(args)
		if err != nil {
			return err
		}
	}

	// Resolve command path
	commandPath, err := exec.LookPath(argv[0])
	if err != nil {
		return fmt.Errorf("command not found: %s", argv[0])
	}

	// Generate secret variants for masking
	maskingSecrets := generateVariants(secrets)

	// Make this process non-dumpable before spawning: the child runs as the same
	// user and is our descendant, so by default it could read our memory and drive
	// our authenticated keychain-auth socket.
	hardenParentProcess()

	// Build child process
	childCmd := exec.Command(commandPath, argv[1:]...)
	childCmd.Env = env
	childCmd.SysProcAttr = childSysProcAttr()
	childCmd.Stdin = os.Stdin
	stdoutMasker := &MaskingWriter{underlying: os.Stdout, secrets: maskingSecrets}
	stderrMasker := &MaskingWriter{underlying: os.Stderr, secrets: maskingSecrets}
	childCmd.Stdout = stdoutMasker
	childCmd.Stderr = stderrMasker

	// Forward signals to child
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case sig := <-sigChan:
			if childCmd.Process != nil {
				childCmd.Process.Signal(sig)
			}
		case <-done:
		}
	}()
	defer func() {
		signal.Stop(sigChan)
		close(done)
	}()

	// Audit is written after the child exits so it can carry the child's identity,
	// exit code and duration. Only key names and hosts are recorded — never values.
	started := time.Now()
	runErr := childCmd.Run()
	_ = stdoutMasker.Flush()
	_ = stderrMasker.Flush()

	if len(secrets) > 0 {
		secretKeys := make([]string, 0, len(secrets))
		for k := range secrets {
			secretKeys = append(secretKeys, k)
		}
		pid := 0
		if childCmd.Process != nil {
			pid = childCmd.Process.Pid
		}
		exitCode := 0
		if runErr != nil {
			if exitErr, ok := runErr.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
		}
		auditLog(project, args, secretKeys, hosts, commandPath, pid, exitCode, time.Since(started))
	}

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			// Propagate the child's exit code via ExitError instead of os.Exit so
			// the deferred signal cleanup here and the telemetry flush in Execute
			// still run. Silent: the child already produced its own output.
			return &ExitError{Code: exitErr.ExitCode(), Silent: true}
		}
		return runErr
	}

	return nil
}

// auditLog records what `env` handed to which child: the key names, the hosts
// those credentials name, and the child's identity, exit code and duration. No
// secret value is ever recorded.
func auditLog(project *config.ProjectConfig, cmdArgs []string, secretKeys, hosts []string, child string, pid, exitCode int, d time.Duration) {
	audit, err := proxy.NewAuditLogger("")
	if err != nil {
		return // non-critical
	}
	defer audit.Close()

	var wsID, projID string
	if project != nil {
		wsID = project.WorkspaceID
		projID = project.ProjectID
	}

	_ = audit.Log(proxy.AuditEvent{
		Timestamp:       time.Now().UTC(),
		SecretKeys:      secretKeys,
		Method:          "ENV",
		TargetURL:       strings.Join(cmdArgs, " "),
		AuthStyles:      []string{"env_inject"},
		StatusCode:      exitCode,
		DurationMs:      d.Milliseconds(),
		Status:          "OK",
		Reason:          "-",
		ResolutionPath:  "env",
		ChildBinary:     child,
		ChildHash:       hashFile(child),
		ChildPID:        pid,
		CredentialHosts: hosts,
		WorkspaceID:     wsID,
		ProjectID:       projID,
	})
}

// hashFile returns "sha256:<hex>" for a file, or "" if it cannot be read.
func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// stripEnv returns env with every entry whose key is in keys removed, so a
// variable this process sets for the child cannot be shadowed by an inherited
// duplicate (the dynamic loader's choice between duplicates is ambiguous).
func stripEnv(env []string, keys []string) []string {
	out := env[:0]
	for _, entry := range env {
		name := entry
		if i := strings.IndexByte(entry, '='); i >= 0 {
			name = entry[:i]
		}
		drop := false
		for _, k := range keys {
			if name == k {
				drop = true
			}
		}
		if !drop {
			out = append(out, entry)
		}
	}
	return out
}

// ensureKeychainAuthForEnv establishes a keychain-auth connection for commands
// that use DisableFlagParsing (env, exec) and therefore skip PersistentPreRunE.
func ensureKeychainAuthForEnv() error {
	if keychainauth.IsInitialized() {
		return nil
	}

	if !keychainauth.IsAvailable() {
		fmt.Println()
		ui.Info("Setting up keychain-auth — this secures your secrets with process-level verification.")
		ui.Info("This is a one-time setup that runs automatically.")
		fmt.Println()

		if err := ui.Spinner("Installing and configuring keychain-auth...", func() error {
			return keychainauth.AutoSetup()
		}); err != nil {
			return fmt.Errorf("keychain-auth is required for secret operations: %w", err)
		}

		ui.Success("keychain-auth configured successfully.")
		fmt.Println()
	}

	if err := keychainauth.Init(); err != nil {
		return fmt.Errorf("%s", keychainauth.UserMessage(err))
	}
	return nil
}

// generateVariants returns all potential encoding/case variants of a secret value.
func generateVariants(secrets map[string]string) []string {
	var variants []string
	seen := make(map[string]bool)

	add := func(v string) {
		if v != "" && !seen[v] && len(v) >= 4 { // Don't mask very short strings to avoid false positives
			variants = append(variants, v)
			seen[v] = true
		}
	}

	for _, value := range secrets {
		if value == "" {
			continue
		}
		// 1. Raw secret
		add(value)

		// 2. Case variants
		add(strings.ToLower(value))
		add(strings.ToUpper(value))

		// 3. Base64 variants
		b64Std := base64.StdEncoding.EncodeToString([]byte(value))
		add(b64Std)
		add(strings.ToLower(b64Std))
		add(strings.ToUpper(b64Std))
		// Raw (unpadded) Std
		b64StdRaw := strings.TrimRight(b64Std, "=")
		add(b64StdRaw)
		add(strings.ToLower(b64StdRaw))
		add(strings.ToUpper(b64StdRaw))

		b64URL := base64.URLEncoding.EncodeToString([]byte(value))
		add(b64URL)
		add(strings.ToLower(b64URL))
		add(strings.ToUpper(b64URL))
		// Raw (unpadded) URL
		b64URLRaw := strings.TrimRight(b64URL, "=")
		add(b64URLRaw)
		add(strings.ToLower(b64URLRaw))
		add(strings.ToUpper(b64URLRaw))

		// 4. Hex variant
		hx := hex.EncodeToString([]byte(value))
		add(hx)
		add(strings.ToUpper(hx))
		// Prefixed Hex
		add("0x" + hx)
		add("0x" + strings.ToUpper(hx))
		add("0X" + hx)
		add("0X" + strings.ToUpper(hx))

		// 5. URL Query Escape
		add(url.QueryEscape(value))
	}
	return variants
}

// MaskingWriter masks secrets in output streams by buffering partial matches across boundaries.
type MaskingWriter struct {
	underlying io.Writer
	secrets    []string
	buf        []byte
}

func (mw *MaskingWriter) Write(p []byte) (n int, err error) {
	if len(mw.secrets) == 0 {
		return mw.underlying.Write(p)
	}

	mw.buf = append(mw.buf, p...)

	// Perform replacements on the accumulated buffer
	content := string(mw.buf)
	for _, secret := range mw.secrets {
		content = strings.ReplaceAll(content, secret, "[REDACTED]")
	}
	mw.buf = []byte(content)

	// Find the longest suffix of mw.buf that is a prefix of any secret
	keepLen := 0
	for _, secret := range mw.secrets {
		for i := 1; i <= len(secret); i++ {
			prefix := secret[:i]
			// Check if buffer ends with this prefix
			if len(mw.buf) >= i && string(mw.buf[len(mw.buf)-i:]) == prefix {
				if i > keepLen {
					keepLen = i
				}
			}
		}
	}

	if keepLen > len(mw.buf) {
		keepLen = len(mw.buf)
	}

	writeLen := len(mw.buf) - keepLen
	if writeLen > 0 {
		_, err = mw.underlying.Write(mw.buf[:writeLen])
		if err != nil {
			return 0, err
		}
		mw.buf = mw.buf[writeLen:]
	}

	return len(p), nil
}

func (mw *MaskingWriter) Flush() error {
	if len(mw.buf) > 0 {
		_, err := mw.underlying.Write(mw.buf)
		mw.buf = nil
		return err
	}
	return nil
}
