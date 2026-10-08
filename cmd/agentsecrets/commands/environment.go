package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/secrets"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var environmentCmd = &cobra.Command{
	Use:     "environment",
	Aliases: []string{"env-switch"},
	Short:   "Manage environments (development, staging, production)",
	Long:    `Switch between environments, list secret counts per environment, and copy or merge secrets across environments.`,
}

var envSwitchCmd = &cobra.Command{
	Use:   "switch <environment>",
	Short: "Switch the active environment",
	Long:  `Changes the active environment. Updates project.json and global config.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runEnvSwitch,
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

	environmentCmd.AddCommand(envSwitchCmd)
	environmentCmd.AddCommand(envListCmd)
	environmentCmd.AddCommand(envCopyCmd)
	environmentCmd.AddCommand(envMergeCmd)
	environmentCmd.AddCommand(envCleanCmd)
}

func runEnvSwitch(cmd *cobra.Command, args []string) error {
	environment := args[0]

	if !config.IsValidEnvironment(environment) {
		return fmt.Errorf("Unknown environment '%s'.\nValid environments: development, staging, production.", environment)
	}

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

	// Update project.json if in a project directory
	p, err := config.LoadProjectConfig()
	if err == nil && p != nil {
		p.Environment = environment
		if err := config.SaveProjectConfig(p); err != nil {
			return fmt.Errorf("failed to update project environment: %w", err)
		}
	}

	// Update global config
	if err := config.SetSelectedEnvironment(environment); err != nil {
		return fmt.Errorf("failed to update global config: %w", err)
	}

	ui.Success(fmt.Sprintf("Switched to %s.", environment))
	ui.Info("Active context:")
	printEnvStatus()
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

	// Try to fetch environment data from API
	type envInfo struct {
		Environment string `json:"environment"`
		SecretCount int    `json:"secret_count"`
	}

	var environments []envInfo

	// Fetch environment data in parallel
	results := make(chan envInfo, 3)
	for _, env := range config.ValidEnvironments {
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

	for i := 0; i < len(config.ValidEnvironments); i++ {
		environments = append(environments, <-results)
	}

	// Sort to match order: development, staging, production
	ordered := make([]envInfo, 3)
	for _, env := range environments {
		switch env.Environment {
		case "development":
			ordered[0] = env
		case "staging":
			ordered[1] = env
		case "production":
			ordered[2] = env
		}
	}
	environments = ordered

	// Fallback if API call failed or returned no data
	if len(environments) == 0 {
		for _, name := range config.ValidEnvironments {
			environments = append(environments, envInfo{
				Environment: name,
				SecretCount: 0,
			})
		}
	}

	fmt.Println()
	for _, env := range environments {
		marker := ""
		if env.Environment == activeEnv {
			marker = "   ← active"
		}
		secretsLabel := "secrets"
		if env.SecretCount == 1 {
			secretsLabel = "secret"
		}
		fmt.Printf("  %-14s %2d %s%s\n", env.Environment, env.SecretCount, secretsLabel, marker)
	}
	fmt.Println()

	return nil
}

func runEnvCopy(cmd *cobra.Command, args []string) error {
	from, to := args[0], args[1]

	if !config.IsValidEnvironment(from) {
		return fmt.Errorf("Unknown environment '%s'.\nValid environments: development, staging, production.", from)
	}
	if !config.IsValidEnvironment(to) {
		return fmt.Errorf("Unknown environment '%s'.\nValid environments: development, staging, production.", to)
	}
	if from == to {
		return fmt.Errorf("Source and destination environments must be different.")
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
	if !confirmProceed(false, "Continue? (y/n): ") {
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
	from, to := args[0], args[1]

	if !config.IsValidEnvironment(from) {
		return fmt.Errorf("Unknown environment '%s'.\nValid environments: development, staging, production.", from)
	}
	if !config.IsValidEnvironment(to) {
		return fmt.Errorf("Unknown environment '%s'.\nValid environments: development, staging, production.", to)
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

func autocompleteEnvironments(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var completions []string
	for _, env := range config.ValidEnvironments {
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
	for _, env := range config.ValidEnvironments {
		if len(args) == 1 && env == args[0] {
			continue
		}
		if strings.HasPrefix(strings.ToLower(env), strings.ToLower(toComplete)) {
			completions = append(completions, env)
		}
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}
