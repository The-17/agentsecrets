package commands

import (
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

	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keychainauth"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/telemetry"
	"github.com/The-17/agentsecrets/pkg/ui"
)

func NewEnvCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "env -- <command> [args...]",
		Short: "Inject secrets as environment variables into a child process",
		Long: `Resolves all secrets from the active project in the OS keychain
		and injects them as environment variables into the specified command.
		The command runs normally with secrets available as env vars.
		Nothing is written to disk. Secrets exist only in the child process memory.`,
		Example: `  agentsecrets env -- stripe mcp
		agentsecrets env -- node server.js
		agentsecrets env -- stripe listen --forward-to localhost:3000`,
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

	// Strip leading -- if present
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return fmt.Errorf("no command specified. Usage: agentsecrets env -- <command> [args...]")
	}

	// Load active project
	project, err := config.LoadProjectConfig()
	if err != nil || project == nil || project.ProjectID == "" {
		return fmt.Errorf("no active project. Run: agentsecrets project use <name>")
	}

	// Ensure keychain-auth session is established before reading secrets.
	// env uses DisableFlagParsing so PersistentPreRunE doesn't fire.
	if err := ensureKeychainAuthForEnv(); err != nil {
		return err
	}

	// Resolve all secrets from keychain
	envName := config.ResolveEnvironment()
	secrets, err := keyring.GetAllProjectSecrets(project.ProjectID, envName)
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
			ui.Info(fmt.Sprintf("Injecting 1 secret: %s", secretKeys[0]))
		} else {
			ui.Info(fmt.Sprintf("Injecting %d secrets: %s + %d more", len(secretKeys), secretKeys[0], len(secretKeys)-1))
		}
	}

	// Build environment: parent env + injected secrets
	env := os.Environ()
	for key, value := range secrets {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// Resolve command path
	commandPath, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("command not found: %s", args[0])
	}

	// Generate secret variants for masking
	maskingSecrets := generateVariants(secrets)

	// Build child process
	childCmd := exec.Command(commandPath, args[1:]...)
	childCmd.Env = env
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

	// Best-effort cloud sync so `env` runs show up in the web audit log like
	// proxy calls do (mirrors LogManagementEvent). The local row is flushed
	// by Close below; sync needs an authenticated session and never fails
	// the command when offline or logged out.
	if apiClient := auth.NewAuthenticatedClient(); apiClient != nil {
		audit.APIClient = apiClient
		_ = audit.SyncUnpushedLogs()
	}
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
