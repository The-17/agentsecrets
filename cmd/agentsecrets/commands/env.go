package commands

import (
	"context"
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
		Use:   "env [--cloud] -- <command> [args...]",
		Short: "Inject secrets as environment variables into a child process",
		Long: `Resolves secrets and injects them as environment variables into the specified command.
		Supports Dual-Engine resolution:
		- Local Engine (Default): Resolves from local OS keychain (offline, 0ms latency).
		- Cloud Engine: Resolves from AgentSecrets Cloud over TLS via AGENTSECRETS_TOKEN or --cloud.
		Nothing is written to disk. Secrets exist only in the child process memory.`,
		Example: `  agentsecrets env -- npm run dev
		agentsecrets env --cloud -- npm run dev
		AGENTSECRETS_TOKEN=agt_prod_... agentsecrets env -- node server.js`,
		RunE:               runEnv,
		DisableFlagParsing: true,
	}
}

func runEnv(cmd *cobra.Command, args []string) error {
	telemetry.RecordIntegration("env")

	// Intercept help flags since DisableFlagParsing is active
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		return cmd.Help()
	}

	// Determine if --cloud flag is passed before --
	useCloud := false
	commandArgs := args

	for i, arg := range args {
		if arg == "--cloud" {
			useCloud = true
		} else if arg == "--" {
			commandArgs = args[i+1:]
			break
		} else if !strings.HasPrefix(arg, "-") {
			commandArgs = args[i:]
			break
		}
	}

	if len(commandArgs) == 0 {
		return fmt.Errorf("no command specified. Usage: agentsecrets env [--cloud] -- <command> [args...]")
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
		project, err := config.LoadProjectConfig()
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

		if len(secrets) == 0 {
			ui.Warning("No secrets found in active project — running without injection")
		} else {
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
	}

	// Build environment: parent env + injected secrets
	env := os.Environ()
	for key, value := range secrets {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// Resolve command path
	commandPath, err := exec.LookPath(commandArgs[0])
	if err != nil {
		return fmt.Errorf("command not found: %s", commandArgs[0])
	}

	// Generate secret variants for masking
	maskingSecrets := generateVariants(secrets)

	// Make this process non-dumpable before spawning: the child runs as the same
	// user and is our descendant, so by default it could read our memory and drive
	// our authenticated keychain-auth socket.
	hardenParentProcess()

	// Build child process
	childCmd := exec.Command(commandPath, commandArgs[1:]...)
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

	// Audit log: key names only
	if len(secrets) > 0 {
		secretKeys := make([]string, 0, len(secrets))
		for k := range secrets {
			secretKeys = append(secretKeys, k)
		}
		auditLog(project, args, secretKeys)
	}

	// Run and exit with child's exit code
	runErr := childCmd.Run()
	_ = stdoutMasker.Flush()
	_ = stderrMasker.Flush()

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

func auditLog(project *config.ProjectConfig, cmdArgs []string, secretKeys []string) {
	audit, err := proxy.NewAuditLogger("")
	if err != nil {
		return // non-critical
	}
	defer audit.Close()

	_ = audit.Log(proxy.AuditEvent{
		Timestamp:   time.Now().UTC(),
		SecretKeys:  secretKeys,
		Method:      "ENV",
		TargetURL:   strings.Join(cmdArgs, " "),
		AuthStyles:  []string{"env_inject"},
		StatusCode:  0,
		Status:      "OK",
		Reason:      "-",
		WorkspaceID: project.WorkspaceID,
		ProjectID:   project.ProjectID,
	})
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
