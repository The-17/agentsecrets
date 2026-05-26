package commands

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/secrets"
	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/The-17/agentsecrets/pkg/workspaces"
)

var (
	secretsService *secrets.Service
	pullForce      bool
	pushForce      bool
	allEnvs        bool
	listRemote     bool
	diffFrom       string
	diffTo         string
)

// InitSecretsService sets up the service for the CLI
func InitSecretsService(client *api.Client) {
	secretsService = secrets.NewService(client)
}

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Manage your secrets",
	Long:  `Add, retrieve, and synchronize secrets for your projects. Secrets are encrypted locally before being stored in the cloud.`,
}

var secretsSetCmd = &cobra.Command{
	Use:   "set KEY=VALUE [KEY2=VALUE2...]",
	Short: "Add or update one or more secrets",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runSecretsSet,
}


var secretsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secret keys in the cloud",
	RunE:  runSecretsList,
}

var secretsPullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Download cloud secrets to your local .env file",
	RunE:  runSecretsPull,
}

var secretsPushCmd = &cobra.Command{
	Use:   "push",
	Short: "Upload local .env secrets to the cloud",
	RunE:  runSecretsPush,
}

var secretsDeleteCmd = &cobra.Command{
	Use:   "delete [key]",
	Short: "Remove a secret from cloud and local files",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsDelete,
}

var secretsDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare local .env with cloud secrets",
	RunE:  runSecretsDiff,
}

func init() {
	secretsPullCmd.Flags().BoolVarP(&pullForce, "force", "f", false, "Overwrite local changes without prompting")
	secretsPushCmd.Flags().BoolVarP(&pushForce, "force", "f", false, "Push without prompting for missing keys")
	secretsListCmd.Flags().BoolVar(&listRemote, "remote", false, "Fetch latest keys from the cloud instead of local cache")
	secretsSetCmd.Flags().BoolVar(&allEnvs, "all-envs", false, "Set in all three environments simultaneously")
	secretsDiffCmd.Flags().StringVar(&diffFrom, "from", "", "Source environment for cross-environment diff")
	secretsDiffCmd.Flags().StringVar(&diffTo, "to", "", "Target environment for cross-environment diff")

	secretsCmd.AddCommand(
		secretsSetCmd,
		secretsListCmd,
		secretsPullCmd,
		secretsPushCmd,
		secretsDeleteCmd,
		secretsDiffCmd,
	)
}

func runSecretsSet(cmd *cobra.Command, args []string) error {
	kv := make(map[string]string)
	for _, arg := range args {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			ui.Error(fmt.Sprintf("Invalid format '%s'. Use KEY=VALUE.", arg))
			continue
		}
		kv[parts[0]] = parts[1]
	}

	if len(kv) == 0 {
		return nil
	}

	if allEnvs {
		// Set in all three environments
		keyNames := make([]string, 0, len(kv))
		for k := range kv {
			keyNames = append(keyNames, k)
		}
		fmt.Printf("This will set %s in development, staging, and production. Continue? (y/n): ", strings.Join(keyNames, ", "))
		if !confirmYN() {
			ui.Info("Cancelled.")
			return nil
		}

		for _, env := range []string{"development", "staging", "production"} {
			if err := ui.Spinner(fmt.Sprintf("Setting in %s...", env), func() error {
				return secretsService.BatchSet(kv, env)
			}); err != nil {
				ui.Error(fmt.Sprintf("Failed to set in %s: %v", env, err))
				continue
			}
			ui.Success(fmt.Sprintf("Set in %s", env))
		}
		return nil
	}

	if err := ui.Spinner(fmt.Sprintf("Encrypting and syncing %d secrets...", len(kv)), func() error {
		return secretsService.BatchSet(kv, "")
	}); err != nil {
		return fmt.Errorf("failed to set secrets: %w", err)
	}

	for k := range kv {
		ui.Success(fmt.Sprintf("Set %s", k))
	}
	return nil
}


func runSecretsList(cmd *cobra.Command, args []string) error {
	if listRemote {
		return runSecretsListRemote(cmd, args)
	}

	project, err := config.LoadProjectConfig()
	if err != nil || project == nil || project.ProjectID == "" {
		return fmt.Errorf("no project configured in current directory")
	}

	activeEnv := config.ResolveEnvironment()
	envs := []string{"development", "staging", "production"}

	presence := make(map[string][3]bool)
	allKeysSet := make(map[string]bool)

	for i, env := range envs {
		keys, err := keyring.ListProjectKeyNames(project.ProjectID, env)
		if err != nil {
			return fmt.Errorf("Could not check (keychain-auth denied request: %w)", err)
		}
		for _, k := range keys {
			p := presence[k]
			p[i] = true
			presence[k] = p
			allKeysSet[k] = true
		}
	}

	if len(allKeysSet) == 0 {
		fmt.Printf("\n%s\n", ui.WarningStyle.Render(fmt.Sprintf("! No secrets found locally in any environment.")))
		fmt.Printf("Use %s to fetch from cloud or %s to add one.\n\n", ui.BrandStyle.Render("agentsecrets secrets pull"), ui.BrandStyle.Render("agentsecrets secrets set KEY=VALUE"))
		return nil
	}

	// Sort keys
	var sortedKeys []string
	for k := range allKeysSet {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	headers := []string{"Key", "DEV", "STAGING", "PROD"}
	rows := make([][]string, len(sortedKeys))

	for i, k := range sortedKeys {
		p := presence[k]
		row := []string{ui.BrandStyle.Render(k)}

		for j := 0; j < 3; j++ {
			if p[j] {
				row = append(row, ui.SuccessStyle.Render("*"))
			} else {
				row = append(row, ui.DimStyle.Render("-"))
			}
		}
		rows[i] = row
	}

	fmt.Printf("\nEnvironment: %s\n\n", ui.BrandStyle.Render(activeEnv))
	fmt.Println(ui.RenderTable(headers, rows))
	fmt.Println()
	ui.Info("Showing cached keys. Use --remote for latest from cloud.")
	return nil
}

func runSecretsListRemote(cmd *cobra.Command, args []string) error {
	activeEnv := config.ResolveEnvironment()
	envs := []string{"development", "staging", "production"}

	type envResult struct {
		env  string
		keys []string
	}
	results := make(chan envResult, 3)
	var wg sync.WaitGroup

	if err := ui.Spinner("Fetching keys from all environments...", func() error {
		for _, e := range envs {
			wg.Add(1)
			go func(envName string) {
				defer wg.Done()
				list, err := secretsService.ListForEnv(envName)
				keys := []string{}
				if err == nil {
					for _, s := range list {
						keys = append(keys, s.Key)
					}
				}
				results <- envResult{env: envName, keys: keys}
			}(e)
		}
		wg.Wait()
		close(results)
		return nil
	}); err != nil {
		ui.Error(fmt.Sprintf("List secrets: %v", err))
		return nil
	}

	// Map of key -> [devPresent, stagingPresent, prodPresent]
	presence := make(map[string][3]bool)
	allKeysSet := make(map[string]bool)

	for res := range results {
		idx := 0
		switch res.env {
		case "development":
			idx = 0
		case "staging":
			idx = 1
		case "production":
			idx = 2
		}
		for _, k := range res.keys {
			p := presence[k]
			p[idx] = true
			presence[k] = p
			allKeysSet[k] = true
		}
	}

	if len(allKeysSet) == 0 {
		fmt.Printf("\n%s\n", ui.WarningStyle.Render(fmt.Sprintf("! No secrets found in any environment.")))
		fmt.Printf("Use %s to add one.\n\n", ui.BrandStyle.Render("agentsecrets secrets set KEY=VALUE"))
		return nil
	}

	// Sort keys
	var sortedKeys []string
	for k := range allKeysSet {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	headers := []string{"Key", "DEV", "STAGING", "PROD"}
	rows := make([][]string, len(sortedKeys))

	for i, k := range sortedKeys {
		p := presence[k]
		row := []string{ui.BrandStyle.Render(k)}

		for j := 0; j < 3; j++ {
			if p[j] {
				row = append(row, ui.SuccessStyle.Render("*"))
			} else {
				row = append(row, ui.DimStyle.Render("-"))
			}
		}
		rows[i] = row
	}

	fmt.Printf("\nEnvironment: %s\n\n", ui.BrandStyle.Render(activeEnv))
	fmt.Println(ui.RenderTable(headers, rows))
	fmt.Println()
	return nil
}

func runSecretsPull(cmd *cobra.Command, args []string) error {
	var diff *secrets.DiffResult

	// 1. Check for conflicts first
	if err := ui.Spinner("Checking for conflicts...", func() error {
		var e error
		diff, e = secretsService.Diff("", "")
		return e
	}); err != nil {
		ui.Error("Failed to check for conflicts: " + err.Error())
		return nil
	}

	hasConflicts := len(diff.Changed) > 0 || len(diff.Removed) > 0
	var targetKeys []string // nil means pull all

	if hasConflicts && !pullForce {
		fmt.Println()
		ui.Warning("Local changes detected that will be overwritten by the cloud version:")

		headers := []string{"Key", "Status"}
		rows := [][]string{}
		for k := range diff.Changed {
			rows = append(rows, []string{ui.BrandStyle.Render(k), ui.WarningStyle.Render("Modified locally")})
		}
		for _, k := range diff.Removed {
			rows = append(rows, []string{ui.BrandStyle.Render(k), ui.ErrorStyle.Render("Only in cloud")})
		}
		fmt.Println(ui.RenderTable(headers, rows))

		var result string
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title("How would you like to resolve these conflicts?").
					Options(
						huh.NewOption("Overwrite All (Cloud Wins)", "overwrite"),
						huh.NewOption("Only Pull Missing (Local Wins)", "missing"),
						huh.NewOption("Cancel", "cancel"),
					).
					Value(&result),
			),
		)

		if err := form.Run(); err != nil {
			return err
		}

		switch result {
		case "cancel":
			ui.Info("Pull cancelled.")
			return nil
		case "missing":
			if len(diff.Removed) == 0 {
				ui.Info("No missing secrets found. Pull cancelled (local changes preserved).")
				return nil
			}
			targetKeys = diff.Removed
		case "overwrite":
			targetKeys = nil // Pull all
		}
	}

	pullCount := len(diff.Removed) + len(diff.Changed) + len(diff.Unchanged)
	if targetKeys != nil {
		pullCount = len(targetKeys)
	}

	if pullCount == 0 {
		ui.Info("No secrets found to pull.")
		return nil
	}

	if err := ui.Spinner(fmt.Sprintf("Pulling %d secrets and allowlist...", pullCount), func() error {
		if err := secretsService.Pull(targetKeys); err != nil {
			return err
		}

		pc, err := config.LoadProjectConfig()
		if err == nil && pc.WorkspaceID != "" {
			domainsResp, err := workspaceService.ListAllowlist(pc.WorkspaceID)
			if err == nil {
				var domains []string
				for _, d := range domainsResp {
					domains = append(domains, d.Domain)
				}
				_ = keyring.SetWorkspaceAllowlist(pc.WorkspaceID, domains)
			}
		}
		return nil
	}); err != nil {
		ui.ErrorWithSuggestions(
			fmt.Errorf("Pull: %w", err),
			"Ensure your local project config is correctly linked: 'agentsecrets status'.",
		)
		return nil
	}

	ui.Success("Successfully synced cloud secrets and allowlist domains.")
	return nil
}

func runSecretsPush(cmd *cobra.Command, args []string) error {
	// 1. Check for keys in cloud that are missing locally
	var diff *secrets.DiffResult

	if err := ui.Spinner("Checking for conflicts...", func() error {
		var e error
		diff, e = secretsService.Diff("", "")
		return e
	}); err != nil {
		ui.Error("Failed to check for conflicts: " + err.Error())
		return nil
	}

	deleteFromCloud := false

	if len(diff.Removed) > 0 && !pushForce {
		fmt.Println()
		ui.Warning("The following keys exist in the cloud but not in your local .env:")

		headers := []string{"Key", "Status"}
		rows := [][]string{}
		for _, k := range diff.Removed {
			rows = append(rows, []string{ui.BrandStyle.Render(k), ui.ErrorStyle.Render("Missing locally")})
		}
		fmt.Println(ui.RenderTable(headers, rows))

		var result string
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title("How would you like to handle these?").
					Options(
						huh.NewOption("Push & Delete Missing from Cloud", "delete"),
						huh.NewOption("Push Only (Keep Cloud Keys)", "keep"),
						huh.NewOption("Cancel", "cancel"),
					).
					Value(&result),
			),
		)

		if err := form.Run(); err != nil {
			return err
		}

		switch result {
		case "cancel":
			ui.Info("Push cancelled.")
			return nil
		case "delete":
			deleteFromCloud = true
		case "keep":
			// Just push, don't delete
		}
	}

	// 2. Push local secrets
	if err := ui.Spinner("Pushing secrets...", func() error {
		return secretsService.Push()
	}); err != nil {
		ui.ErrorWithSuggestions(
			fmt.Errorf("Push: %w", err),
			"Ensure you have an active network connection and are logged in.",
			"Check that you are authorized to push to this environment (e.g. check your permissions).",
		)
		return nil
	}

	ui.Success("Successfully pushed local secrets to the cloud sync service.")

	// 3. Delete missing keys from cloud if requested
	if deleteFromCloud && len(diff.Removed) > 0 {
		if err := ui.Spinner(fmt.Sprintf("Deleting %d missing keys from cloud...", len(diff.Removed)), func() error {
			for _, key := range diff.Removed {
				if err := secretsService.Delete(key); err != nil {
					return fmt.Errorf("failed to delete %s: %w", key, err)
				}
			}
			return nil
		}); err != nil {
			ui.Error(fmt.Sprintf("Delete: %v", err))
			return nil
		}

		for _, k := range diff.Removed {
			ui.Success(fmt.Sprintf("Deleted %s from cloud", k))
		}
	}

	return nil
}

func runSecretsDelete(cmd *cobra.Command, args []string) error {
	key := args[0]

	// Confirm before deleting from production
	env := config.ResolveEnvironment()
	if env == "production" {
		fmt.Printf("Delete %s from production? (y/n): ", key)
		if !confirmYN() {
			ui.Info("Delete cancelled.")
			return nil
		}
	}

	if err := ui.Spinner(fmt.Sprintf("Deleting %s...", key), func() error {
		return secretsService.Delete(key)
	}); err != nil {
		ui.Error(fmt.Sprintf("Delete: %v", err))
		return nil
	}

	ui.Success(fmt.Sprintf("Deleted %s from cloud and local files.", key))
	return nil
}

func runSecretsDiff(cmd *cobra.Command, args []string) error {
	var diff *secrets.DiffResult

	if err := ui.Spinner("Comparing secrets & allowlist...", func() error {
		var e error
		diff, e = secretsService.Diff(diffFrom, diffTo)
		return e
	}); err != nil {
		ui.Error(fmt.Sprintf("Diff: %v", err))
		return nil
	}

	pc, _ := config.LoadProjectConfig()
	var allowlistRemote []workspaces.AllowlistDomain
	var allowlistLocal []string
	if pc != nil && pc.WorkspaceID != "" {
		if remote, err := workspaceService.ListAllowlist(pc.WorkspaceID); err == nil {
			allowlistRemote = remote
		}
		if local, err := keyring.GetWorkspaceAllowlist(pc.WorkspaceID); err == nil {
			allowlistLocal = local
		}
	}

	fmt.Printf("\n%s\n", ui.BannerStr("Secret Diff"))

	allowlistDrift := false
	// Calculate remote only allowlist drift
	var remoteOnlyAllowlist []string
	for _, r := range allowlistRemote {
		found := false
		for _, l := range allowlistLocal {
			if strings.ToLower(l) == strings.ToLower(r.Domain) {
				found = true
				break
			}
		}
		if !found {
			remoteOnlyAllowlist = append(remoteOnlyAllowlist, r.Domain)
			allowlistDrift = true
		}
	}
	// Calculate local only allowlist drift
	var localOnlyAllowlist []string
	for _, l := range allowlistLocal {
		found := false
		for _, r := range allowlistRemote {
			if strings.ToLower(l) == strings.ToLower(r.Domain) {
				found = true
				break
			}
		}
		if !found {
			localOnlyAllowlist = append(localOnlyAllowlist, l)
			allowlistDrift = true
		}
	}

	sourceName := "Local"
	if diffFrom != "" {
		sourceName = upperFirst(diffFrom)
	}
	targetName := "Cloud"
	if diffTo != "" {
		targetName = upperFirst(diffTo)
	} else {
		targetName = upperFirst(config.ResolveEnvironment())
	}

	// The SECRETS block will now always print and show what's identical.

	if len(diff.Added) > 0 || len(diff.Removed) > 0 || len(diff.Changed) > 0 || len(diff.Unchanged) > 0 {
		fmt.Printf("SECRETS:\n")

		fmt.Printf("\n  %s %s but missing in %s:\n", ui.LabelStyle.Render("In"), ui.BrandStyle.Render(sourceName), ui.BrandStyle.Render(targetName))
		if len(diff.Added) > 0 {
			for _, k := range diff.Added {
				fmt.Printf("    %s\n", ui.SuccessStyle.Render(k))
			}
		} else {
			fmt.Printf("    %s\n", ui.DimStyle.Render("(none)"))
		}

		fmt.Printf("\n  %s %s but missing in %s:\n", ui.LabelStyle.Render("In"), ui.BrandStyle.Render(targetName), ui.BrandStyle.Render(sourceName))
		if len(diff.Removed) > 0 {
			for _, k := range diff.Removed {
				fmt.Printf("    %s\n", ui.ErrorStyle.Render(k))
			}
		} else {
			fmt.Printf("    %s\n", ui.DimStyle.Render("(none)"))
		}

		if len(diff.Changed) > 0 {
			fmt.Printf("\n  %s %s but values differ:\n", ui.LabelStyle.Render("In"), ui.BrandStyle.Render("both"))
			for k := range diff.Changed {
				fmt.Printf("    %s\n", ui.WarningStyle.Render(k))
			}
		}

		if len(diff.Unchanged) > 0 {
			fmt.Printf("\n  %s %s and identical:\n", ui.LabelStyle.Render("In"), ui.BrandStyle.Render("both"))
			for _, k := range diff.Unchanged {
				fmt.Printf("    %s\n", ui.DimStyle.Render(k))
			}
		}
		fmt.Println()
	}

	if allowlistDrift {
		fmt.Printf("ALLOWLIST:\n")
		if len(remoteOnlyAllowlist) > 0 {
			fmt.Printf("  %s %s\n", strings.TrimSpace(ui.ErrorStyle.Render("REMOTE ONLY:")), strings.Join(remoteOnlyAllowlist, ", "))
		}
		if len(localOnlyAllowlist) > 0 {
			fmt.Printf("  %s  %s\n", strings.TrimSpace(ui.SuccessStyle.Render("LOCAL ONLY:")), strings.Join(localOnlyAllowlist, ", "))
		}
		fmt.Println()
	}
	if diffFrom == "" {
		if len(diff.Added) > 0 {
			fmt.Printf("Run %s to upload local changes.\n", ui.BrandStyle.Render("agentsecrets secrets push"))
		}
		if len(diff.Removed) > 0 || len(diff.Changed) > 0 || allowlistDrift {
			fmt.Printf("Run %s to sync from cloud.\n", ui.BrandStyle.Render("agentsecrets secrets pull"))
		}
		fmt.Println()
	}

	return nil
}

// upperFirst capitalises the first letter of a string.
func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
