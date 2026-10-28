package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/secrets"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var environmentCmd = &cobra.Command{
	Use:     "environment",
	Aliases: []string{"env-switch"},
	Short:   "Manage environments (standard and custom)",
	Long: `Switch between environments, list secret counts per environment, and copy or merge secrets across environments.

An environment is any name matching ` + config.EnvironmentNameRule + `. The standard three are ` + strings.Join(config.StandardEnvironments, ", ") + `.`,
}

var envSwitchCmd = &cobra.Command{
	Use:   "switch <environment>",
	Short: "Switch the active environment",
	Long:  `Changes the active environment. Updates project.json and global config.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runEnvSwitch,
}

var envCreateCmd = &cobra.Command{
	Use:   "create <environment>",
	Short: "Create a custom environment (Pro)",
	Long: `Creates a custom environment and switches to it.

Custom environments are a Pro feature. The standard three (` + strings.Join(config.StandardEnvironments, ", ") + `) already exist in every project.

An environment exists once it holds a secret, so the next step is to store one.`,
	Args: cobra.ExactArgs(1),
	RunE: runEnvCreate,
}

var envListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all environments with secret counts",
	RunE:  runEnvList,
}

var envCopyCmd = &cobra.Command{
	Use:   "copy <from> <to>",
	Short: "Copy all secrets from one environment to another",
	Long:  `Copies all secrets from the source environment to the destination with identical values. Confirms before overwriting.`,
	Args:  cobra.ExactArgs(2),
	RunE:  runEnvCopy,
}

var envMergeCmd = &cobra.Command{
	Use:   "merge <from> <to>",
	Short: "Merge secrets from one environment to another with new values",
	Long:  `Takes key names from the source environment and prompts you to enter new values for the destination. Press Enter to skip a key.`,
	Args:  cobra.ExactArgs(2),
	RunE:  runEnvMerge,
}

var envCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Delete all secrets in the current environment",
	Long:  "Fetches all secrets for the active environment and deletes them from cloud, .env, and keychain after confirmation.",
	RunE:  runEnvClean,
}

func init() {
	envSwitchCmd.ValidArgsFunction = autocompleteEnvironments
	envCopyCmd.ValidArgsFunction = autocompleteEnvironmentsMulti
	envMergeCmd.ValidArgsFunction = autocompleteEnvironmentsMulti
	envCopyCmd.Flags().BoolP("yes", "y", false, "skip the overwrite confirmation (required when there is no terminal)")

	environmentCmd.AddCommand(envSwitchCmd)
	environmentCmd.AddCommand(envCreateCmd)
	environmentCmd.AddCommand(envListCmd)
	environmentCmd.AddCommand(envCopyCmd)
	environmentCmd.AddCommand(envMergeCmd)
	environmentCmd.AddCommand(envCleanCmd)
}

func runEnvSwitch(cmd *cobra.Command, args []string) error {
	environment, err := config.ParseEnvironment(args[0])
	if err != nil {
		return err
	}
	if err := requireProForCustomEnvironment(environment); err != nil {
		return err
	}

	// Switching to a name nobody has used yet is legitimate: that is how a new
	// custom environment starts. Say so quietly rather than refusing, because a
	// typo would otherwise look identical to a working environment and a later
	// `secrets push` would store real secrets under the misspelled name.
	warnIfEnvironmentUnused(environment)

	// Check for potentially unsaved local changes
	prevEnv := config.ResolveEnvironment()
	localEnvFile := fmt.Sprintf(".env.%s", prevEnv)
	if _, err := os.Stat(localEnvFile); err == nil {
		ui.Warning(fmt.Sprintf("You may have unpushed changes in %s.", prevEnv))
		ui.Info("Run 'agentsecrets secrets push' first if you want to save them.")
		if !confirmProceed(false, "Switch anyway? (y/n): ") {
			return nil
		}
	}

	if err := setActiveEnvironment(environment); err != nil {
		return err
	}

	ui.Success(fmt.Sprintf("Switched to %s.", environment))
	ui.Info("Active context:")
	printEnvStatus()
	return nil
}

// setActiveEnvironment makes environment the one every later command resolves.
// It writes project.json when there is a project and always writes the global
// selection, so a switch survives leaving the directory.
func setActiveEnvironment(environment string) error {
	if p, err := config.LoadProjectConfig(); err == nil && p != nil {
		p.Environment = environment
		if err := config.SaveProjectConfig(p); err != nil {
			return fmt.Errorf("failed to update project environment: %w", err)
		}
	}
	if err := config.SetSelectedEnvironment(environment); err != nil {
		return fmt.Errorf("failed to update global config: %w", err)
	}
	return nil
}

func runEnvCreate(cmd *cobra.Command, args []string) error {
	environment, err := config.ParseEnvironment(args[0])
	if err != nil {
		return err
	}
	if config.IsStandardEnvironment(environment) {
		return fmt.Errorf(
			"%q is a standard environment and already exists. Switch to it with 'agentsecrets environment switch %s'",
			environment, environment,
		)
	}
	if err := requireProForCustomEnvironment(environment); err != nil {
		return err
	}
	if err := setActiveEnvironment(environment); err != nil {
		return err
	}

	ui.Success(fmt.Sprintf("Created %s and switched to it.", environment))
	ui.Info("Store the first secret with 'agentsecrets secrets set KEY=VALUE'.")
	return nil
}

func printEnvStatus() {
	p, _ := config.LoadProjectConfig()
	global, _ := config.LoadGlobalConfig()

	wsName := "—"
	if global != nil && global.SelectedWorkspaceID != "" {
		if ws, ok := global.Workspaces[global.SelectedWorkspaceID]; ok {
			wsName = ws.Name
		}
	}
	projName := "—"
	if p != nil && p.ProjectName != "" {
		projName = p.ProjectName
	}
	env := config.ResolveEnvironment()

	ui.StatusRow("Workspace", wsName)
	ui.StatusRow("Project", projName)
	ui.StatusRow("Environment", env)
}

func runEnvList(cmd *cobra.Command, args []string) error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return fmt.Errorf("no project configured. Run 'agentsecrets project use <name>' first")
	}

	activeEnv := config.ResolveEnvironment()

	root, _ := config.GetProjectRoot()
	environments, err := app.Secrets().Environments(project.ProjectID, root)
	if err != nil {
		return err
	}

	// Try to fetch environment data from API
	type envInfo struct {
		Environment string `json:"environment"`
		SecretCount int    `json:"secret_count"`
	}

	// Fetch environment data in parallel
	results := make(chan envInfo, len(environments))
	for _, env := range environments {
		go func(e string) {
			count := 0
			resp, err := app.API().Call("secrets.list", "GET", nil, map[string]string{
				"project_id": project.ProjectID,
			}, map[string]string{
				"environment": e,
			})
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					var res struct {
						Data struct {
							Secrets []interface{} `json:"secrets"`
						} `json:"data"`
					}
					if err := json.NewDecoder(resp.Body).Decode(&res); err == nil {
						count = len(res.Data.Secrets)
					}
				}
			}
			results <- envInfo{Environment: e, SecretCount: count}
		}(env)
	}

	counts := make(map[string]int, len(environments))
	for i := 0; i < len(environments); i++ {
		info := <-results
		counts[info.Environment] = info.SecretCount
	}

	fmt.Println()
	for _, name := range environments {
		count := counts[name]
		marker := ""
		if name == activeEnv {
			marker = "   ← active"
		}
		secretsLabel := "secrets"
		if count == 1 {
			secretsLabel = "secret"
		}
		fmt.Printf("  %-14s %2d %s%s\n", name, count, secretsLabel, marker)
	}
	fmt.Println()

	return nil
}

func runEnvCopy(cmd *cobra.Command, args []string) error {
	from, err := config.ParseEnvironment(args[0])
	if err != nil {
		return err
	}
	to, err := config.ParseEnvironment(args[1])
	if err != nil {
		return err
	}
	if from == to {
		return fmt.Errorf("Source and destination environments must be different.")
	}
	if err := requireProForCustomEnvironment(to); err != nil {
		return err
	}

	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return fmt.Errorf("no project configured. Run 'agentsecrets project use <name>' first")
	}

	wsKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return fmt.Errorf("failed to get workspace key: %w", err)
	}

	// Fetch all secrets for 'from' environment
	var fromSecrets []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}

	if err := ui.Spinner(fmt.Sprintf("Fetching secrets from %s...", from), func() error {
		resp, err := app.API().Call("secrets.list", "GET", nil, map[string]string{
			"project_id": project.ProjectID,
		}, map[string]string{
			"environment": from,
		})
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return app.API().DecodeError(resp)
		}
		var res struct {
			Data struct {
				Secrets []struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				} `json:"secrets"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return err
		}
		fromSecrets = res.Data.Secrets
		return nil
	}); err != nil {
		return fmt.Errorf("failed to fetch secrets from %s: %w", from, err)
	}

	if len(fromSecrets) == 0 {
		ui.Info(fmt.Sprintf("No secrets found in %s. Nothing to copy.", from))
		return nil
	}

	// Confirm if destination has existing secrets
	ui.Info(fmt.Sprintf("This will copy %d secrets from %s to %s.", len(fromSecrets), from, to))
	yes, _ := cmd.Flags().GetBool("yes")
	if !yes && !term.IsTerminal(int(os.Stdin.Fd())) {
		// Reading a confirmation from a pipe would block or silently cancel.
		// Say what to pass instead.
		return errors.New(errors.ErrUsage,
			fmt.Sprintf("refusing to overwrite %s without confirmation in a non-interactive shell", to),
			fmt.Errorf("re-run with --yes"))
	}
	if !confirmProceed(yes, "Continue? (y/n): ") {
		ui.Info("Copy cancelled.")
		return nil
	}

	if err := ui.Spinner(fmt.Sprintf("Copying %d secrets to %s...", len(fromSecrets), to), func() error {
		kv := make(map[string]string)
		for _, s := range fromSecrets {
			plaintext, _ := crypto.DecryptSecret(s.Value, wsKey)
			kv[s.Key] = plaintext
		}

		return app.Secrets().BatchSet(kv, to)
	}); err != nil {
		return fmt.Errorf("copy failed: %w", err)
	}

	ui.Success(fmt.Sprintf("Copied %d secrets from %s to %s.", len(fromSecrets), from, to))
	return nil
}

func runEnvMerge(cmd *cobra.Command, args []string) error {
	from, err := config.ParseEnvironment(args[0])
	if err != nil {
		return err
	}
	to, err := config.ParseEnvironment(args[1])
	if err != nil {
		return err
	}
	if err := requireProForCustomEnvironment(to); err != nil {
		return err
	}

	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return fmt.Errorf("no project configured. Run 'agentsecrets project use <name>' first")
	}

	wsKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return fmt.Errorf("failed to get workspace key: %w", err)
	}

	// Fetch secrets from source
	type secretEntry struct {
		Key   string
		Value string // encrypted
	}
	var fromSecrets []secretEntry

	if err := ui.Spinner(fmt.Sprintf("Fetching keys from %s...", from), func() error {
		resp, err := app.API().Call("secrets.list", "GET", nil, map[string]string{
			"project_id": project.ProjectID,
		}, map[string]string{
			"environment": from,
		})
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return app.API().DecodeError(resp)
		}
		var res struct {
			Data struct {
				Secrets []struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				} `json:"secrets"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return err
		}
		for _, s := range res.Data.Secrets {
			fromSecrets = append(fromSecrets, secretEntry{Key: s.Key, Value: s.Value})
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to fetch secrets from %s: %w", from, err)
	}

	if len(fromSecrets) == 0 {
		ui.Info(fmt.Sprintf("No secrets found in %s. Nothing to merge.", from))
		return nil
	}

	// Prompt for each key
	ui.Info(fmt.Sprintf("Enter %s values for each key (press Enter to keep %s values):", to, from))
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	var toSet []map[string]string
	kept := 0
	updated := 0

	for _, s := range fromSecrets {
		// Mask the source value: show first 3 chars + ***
		plaintext, _ := crypto.DecryptSecret(s.Value, wsKey)
		masked := maskValue(plaintext)

		fmt.Printf("%s (%s: %s) [Enter to keep]: ", s.Key, from, masked)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			toSet = append(toSet, map[string]string{"key": s.Key, "value": s.Value})
			kept++
			continue
		}

		// Encrypt the new value
		encrypted, err := crypto.EncryptSecret(input, wsKey)
		if err != nil {
			ui.Error(fmt.Sprintf("Failed to encrypt %s: %v", s.Key, err))
			continue
		}
		toSet = append(toSet, map[string]string{"key": s.Key, "value": encrypted})
		updated++
	}

	if len(toSet) == 0 {
		ui.Info("No keys processed. Nothing to merge.")
		return nil
	}

	// Push to destination environment
	if err := ui.Spinner(fmt.Sprintf("Updating %d secrets in %s...", len(toSet), to), func() error {
		kv := make(map[string]string)
		for _, s := range toSet {
			plaintext, _ := crypto.DecryptSecret(s["value"], wsKey)
			kv[s["key"]] = plaintext
		}
		return app.Secrets().BatchSet(kv, to)
	}); err != nil {
		return fmt.Errorf("merge failed: %w", err)
	}

	ui.Success(fmt.Sprintf("%d secrets successfully processed in %s.", len(toSet), to))
	ui.Info(fmt.Sprintf("(%d updated, %d kept)", updated, kept))
	return nil
}

// maskValue shows the first 3 chars + *** for masking source secret previews.
func maskValue(val string) string {
	if len(val) <= 3 {
		return "***"
	}
	return val[:3] + "***"
}

func runEnvClean(cmd *cobra.Command, args []string) error {
	activeEnv := config.ResolveEnvironment()

	var list []secrets.SecretMetadata
	if err := ui.Spinner("Fetching secrets...", func() error {
		var e error
		list, e = app.Secrets().List() // uses active env
		return e
	}); err != nil {
		return err
	}

	if len(list) == 0 {
		fmt.Printf("\n%s\n", ui.DimStyle.Render(fmt.Sprintf("No secrets found in %s environment.", activeEnv)))
		return nil
	}

	fmt.Printf("\n%s\n", ui.WarningStyle.Render(fmt.Sprintf("! WARNING: This will delete all %d secrets in %s environment.", len(list), activeEnv)))
	if !confirmProceed(false, "This action cannot be undone. Continue? (y/n): ") {
		ui.Info("Clean cancelled.")
		return nil
	}

	if activeEnv == "production" {
		if err := verifyPasswordLocally(); err != nil {
			return err
		}
	}

	for _, s := range list {
		if err := ui.Spinner(fmt.Sprintf("Deleting %s...", s.Key), func() error {
			return app.Secrets().Delete(s.Key)
		}); err != nil {
			ui.Error(fmt.Sprintf("Failed to delete %s: %v", s.Key, err))
		}
	}

	ui.Success(fmt.Sprintf("Cleaned %s environment.", activeEnv))
	return nil
}

// warnIfEnvironmentUnused tells the user when they switched to a name no project
// environment or local cache knows about. It never blocks: a custom environment
// has to start somewhere, and the first `secrets set` is a valid way to start it.
func warnIfEnvironmentUnused(environment string) {
	p, err := config.LoadProjectConfig()
	if err != nil || p == nil || p.ProjectID == "" {
		return
	}
	for _, known := range knownEnvironments() {
		if known == environment {
			return
		}
	}
	ui.Warning(fmt.Sprintf("No secrets are stored in %q yet.", environment))
	ui.Info("Set one with 'agentsecrets secrets set KEY=VALUE' to start this environment.")
}

// knownEnvironments lists the project's environments, standard three first. It
// asks the control plane because the local cache can only see names this
// machine has touched, and a custom environment created on the dashboard would
// otherwise be invisible. Offline, it falls back to the local list, then to the
// standard three.
func knownEnvironments() []string {
	p, err := config.LoadProjectConfig()
	if err != nil || p == nil || p.ProjectID == "" {
		return config.StandardEnvironments
	}
	root, _ := config.GetProjectRoot()
	environments, err := app.Secrets().Environments(p.ProjectID, root)
	if err != nil {
		return config.StandardEnvironments
	}
	return environments
}

func autocompleteEnvironments(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var completions []string
	for _, env := range knownEnvironments() {
		if strings.HasPrefix(strings.ToLower(env), strings.ToLower(toComplete)) {
			completions = append(completions, env)
		}
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func autocompleteEnvironmentsMulti(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) >= 2 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var completions []string
	for _, env := range knownEnvironments() {
		if len(args) == 1 && env == args[0] {
			continue
		}
		if strings.HasPrefix(strings.ToLower(env), strings.ToLower(toComplete)) {
			completions = append(completions, env)
		}
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}
