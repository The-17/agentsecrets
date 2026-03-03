package commands

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/proxy"
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

	// Resolve all secrets from keychain
	secrets, err := keyring.GetAllProjectSecrets(project.ProjectID)
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
		ui.Info(fmt.Sprintf("Injecting %d secret(s): %s", len(secrets), strings.Join(secretKeys, ", ")))
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

	// Build child process
	childCmd := exec.Command(commandPath, args[1:]...)
	childCmd.Env = env
	childCmd.Stdin = os.Stdin
	childCmd.Stdout = os.Stdout
	childCmd.Stderr = os.Stderr

	// Forward signals to child
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		if childCmd.Process != nil {
			childCmd.Process.Signal(sig)
		}
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
	if err := childCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
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
		Timestamp:  time.Now().UTC(),
		SecretKeys: secretKeys,
		Method:     "ENV",
		TargetURL:  strings.Join(cmdArgs, " "),
		AuthStyles: []string{"env_inject"},
		StatusCode: 0,
		Status:     "OK",
		Reason:     "-",
	})
}
