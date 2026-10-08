package commands

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/secrets"
	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/The-17/agentsecrets/pkg/workspaces"
)

var (
	pullForce  bool
	pushForce  bool
	allEnvs    bool
	listRemote bool
	diffFrom   string
	diffTo     string
)

// secretExists reports whether a secret key exists for the given project/env.
// It checks the local keychain first, then falls back to the remote list so a
// key present only in the cloud (e.g. before a pull) is still recognised.
func secretExists(projectID, env, key string) (bool, error) {
	exists, err := keyring.SecretExists(projectID, env, key)
	if err != nil {
		return false, fmt.Errorf("failed to check if secret exists: %w", err)
	}
	if exists {
		return true, nil
	}
	if remoteKeys, err := app.Secrets().ListForEnv(env); err == nil {
		for _, k := range remoteKeys {
			if strings.EqualFold(k.Key, key) {
				return true, nil
			}
		}
	}
	return false, nil
}

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Manage your secrets",
	Long:  `Add and synchronize secrets for your projects. Secrets are encrypted locally before being stored in the cloud.`,
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
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureDaemonInitialized(); err != nil {
			return err
		}
		if listRemote {
			return app.Auth().EnsureAuth(cmd, args)
		}
		return nil
	},
	RunE: runSecretsList,
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

var secretsRotateCmd = &cobra.Command{
	Use:   "rotate KEY",
	Short: "Rotate a secret value: stage a pending version, promote it, or roll back (B1 client-push)",
	Long: `Two-step rotation. First stage a new client-encrypted value as pending,
update the value at the provider out-of-band, then promote. The old value
stays valid at the provider through the overlap window (routine) or dies
immediately (compromise).`,
	Args: cobra.ExactArgs(1),
	RunE: runSecretsRotate,
}

var secretsRotationCmd = &cobra.Command{
	Use:   "rotation",
	Short: "Manage secret rotation cadence and status",
}

var secretsRotationSetCmd = &cobra.Command{
	Use:   "set KEY",
	Short: "Arm (or disarm) an automated rotation cadence for a secret",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsRotationSet,
}

var secretsRotationStatusCmd = &cobra.Command{
	Use:   "status KEY",
	Short: "Show a secret's rotation policy and version history",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsRotationStatus,
}

func runSecretsRotate(cmd *cobra.Command, args []string) error {
	key := args[0]
	env, _ := cmd.Flags().GetString("env")
	inlineValue, _ := cmd.Flags().GetString("value")
	generate, _ := cmd.Flags().GetBool("generate")
	genLength, _ := cmd.Flags().GetInt("length")
	doPromote, _ := cmd.Flags().GetBool("promote")
	doRollback, _ := cmd.Flags().GetBool("rollback")
	doAbort, _ := cmd.Flags().GetBool("abort")
	reason, _ := cmd.Flags().GetString("reason")
	expectedCurrent, _ := cmd.Flags().GetString("expected-current")
	confirm, _ := cmd.Flags().GetBool("confirm")

	ops := 0
	for _, on := range []bool{doPromote, doRollback, doAbort} {
		if on {
			ops++
		}
	}
	staging := inlineValue != "" || generate
	if ops > 1 || (ops == 1 && staging) {
		return fmt.Errorf("use one action per invocation: stage (default), --promote, --rollback, or --abort")
	}
	if reason != "routine" && reason != "compromise" {
		return fmt.Errorf("--reason must be routine or compromise")
	}
	if doPromote && reason == "compromise" {
		fmt.Println(ui.WarningStyle.Render("Compromise rotation: zero overlap, previous value shredded."))
	}

	svc := app.Secrets()

	if doRollback {
		if !confirmProceed(confirm, fmt.Sprintf("Roll back %s to its previous value? (y/n): ", key)) {
			ui.Info("Cancelled.")
			return nil
		}
		res, err := svc.RollbackVersion(key, env)
		if err != nil {
			return fmt.Errorf("rollback failed: %w", err)
		}
		if err := svc.Pull([]string{res.Key}); err != nil {
			ui.Error(fmt.Sprintf("Rolled back cloud-side, but local resync failed: %v", err))
		}
		ui.Success(fmt.Sprintf("Rolled back %s to its previous value.", res.Key))
		return nil
	}

	if doAbort {
		if err := svc.AbortPending(key, env); err != nil {
			return fmt.Errorf("abort failed: %w", err)
		}
		ui.Success(fmt.Sprintf("Aborted pending rotation for %s.", key))
		return nil
	}

	if doPromote {
		if !confirmProceed(confirm, fmt.Sprintf("Promote the pending version of %s to current? (y/n): ", key)) {
			ui.Info("Cancelled.")
			return nil
		}
		if reason == "compromise" || config.ResolveEnvironment() == "production" {
			if err := verifyPasswordLocally(); err != nil {
				return err
			}
		}
		res, err := svc.PromoteVersion(key, env, expectedCurrent, reason)
		if err != nil {
			return fmt.Errorf("promote failed: %w", err)
		}
		if err := svc.Pull([]string{res.Key}); err != nil {
			ui.Error(fmt.Sprintf("Promoted cloud-side, but local resync failed: %v", err))
		}
		if reason == "compromise" {
			ui.Success(fmt.Sprintf("Promoted %s with zero overlap; previous value shredded.", res.Key))
		} else {
			ui.Success(fmt.Sprintf("Promoted %s; old value stays valid at the provider through overlap.", res.Key))
		}
		return nil
	}

	var plaintext string
	switch {
	case inlineValue != "":
		plaintext = inlineValue
	case generate:
		if err := verifyPasswordLocally(); err != nil {
			return err
		}
		pw, err := crypto.GeneratePassword(genLength)
		if err != nil {
			return err
		}
		plaintext = pw
		fmt.Printf("Generated value for %s: %s\n", key, plaintext)
		fmt.Println(ui.WarningStyle.Render("Store it at the provider before promoting."))
	default:
		var input string
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("New value for " + key).
					Password(true).
					Value(&input),
			),
		)
		if err := form.Run(); err != nil {
			return err
		}
		plaintext = input
	}
	if plaintext == "" {
		return fmt.Errorf("empty value: nothing staged")
	}

	staged, _, err := svc.StageVersion(key, plaintext, env, reason)
	if err != nil {
		return fmt.Errorf("stage failed: %w", err)
	}
	ui.Success(fmt.Sprintf("Staged pending version %s for %s.", staged.VersionID, key))
	fmt.Printf("Next: update the value at the provider, then run 'agentsecrets secrets rotate %s --promote'.\n", key)
	return nil
}

func runSecretsRotationSet(cmd *cobra.Command, args []string) error {
	key := args[0]
	env, _ := cmd.Flags().GetString("env")
	policyType, _ := cmd.Flags().GetString("type")
	periodDays, _ := cmd.Flags().GetInt("period-days")
	overlapHours, _ := cmd.Flags().GetInt("overlap-hours")
	disable, _ := cmd.Flags().GetBool("disable")

	if disable == (periodDays <= 0) {
		return fmt.Errorf("provide --period-days (>0) to arm, or --disable to disarm")
	}
	if !disable {
		switch policyType {
		case "value_client", "value_auto", "value_provider":
		default:
			return fmt.Errorf("--type must be value_client, value_auto, or value_provider")
		}
		if policyType == "value_auto" {
			fmt.Println(ui.WarningStyle.Render("Autonomous rotation: the Cloud Resolver will mint new values on cadence (Pro). Trust-anchor keys are refused server-side."))
		}
		if policyType == "value_provider" {
			adapter, _ := cmd.Flags().GetString("adapter")
			adapterRef, _ := cmd.Flags().GetString("adapter-ref")
			adminRef, _ := cmd.Flags().GetString("admin-credential-ref")
			targetUser, _ := cmd.Flags().GetString("target-user")
			if adapterRef != "" {
				id, _, ok := strings.Cut(adapterRef, "@")
				if !ok || id == "" {
					return fmt.Errorf("--adapter-ref must be <id>@<version>[#sha256:<hex>]")
				}
				if adapter != "" && adapter != id {
					return fmt.Errorf("--adapter (%s) must match --adapter-ref id (%s)", adapter, id)
				}
				adapter = id
			}
			if adapter == "" || adminRef == "" || targetUser == "" {
				return fmt.Errorf("value_provider requires --adapter (or --adapter-ref), --admin-credential-ref, and --target-user")
			}
			fmt.Println(ui.WarningStyle.Render("Provider rotation: the Cloud Resolver will change the credential AT THE PROVIDER on cadence (Pro, isolated executor). The admin credential must live in the same project/environment."))
		}
	}
	req := secrets.RotationPolicy{Enabled: !disable}
	if !disable {
		req.Type = policyType
		req.PeriodDays = &periodDays
		if cmd.Flags().Changed("overlap-hours") {
			req.OverlapHours = &overlapHours
		}
		if policyType == "value_provider" {
			adapter, _ := cmd.Flags().GetString("adapter")
			adapterRef, _ := cmd.Flags().GetString("adapter-ref")
			adminRef, _ := cmd.Flags().GetString("admin-credential-ref")
			targetUser, _ := cmd.Flags().GetString("target-user")
			if adapterRef != "" {
				id, _, _ := strings.Cut(adapterRef, "@")
				adapter = id // validated consistent above
			}
			binding := map[string]any{
				"adapter": adapter, "admin_credential_ref": adminRef, "target_user": targetUser,
			}
			if adapterRef != "" {
				binding["adapter_ref"] = adapterRef
			}
			if cmd.Flags().Changed("length-bytes") {
				lengthBytes, _ := cmd.Flags().GetInt("length-bytes")
				binding["length_bytes"] = lengthBytes
			}
			req.Binding = binding
		}
	}
	if err := app.Secrets().SetRotationPolicy(key, env, req); err != nil {
		return fmt.Errorf("rotation policy update failed: %w", err)
	}
	if disable {
		ui.Success(fmt.Sprintf("Disarmed rotation cadence for %s.", key))
		return nil
	}
	ui.Success(fmt.Sprintf("Armed %s rotation every %d days for %s.", policyType, periodDays, key))
	fmt.Println("Execution and reminders are Pro-gated in the Cloud Resolver; manual rotate stays free.")
	return nil
}

func runSecretsRotationStatus(cmd *cobra.Command, args []string) error {
	key := args[0]
	env, _ := cmd.Flags().GetString("env")

	status, err := app.Secrets().RotationStatus(key, env)
	if err != nil {
		return fmt.Errorf("rotation status failed: %w", err)
	}
	fmt.Printf("Secret  %s (%s)\n", status.Key, status.Environment)
	if typ, _ := status.Policy["rotation_type"].(string); typ != "" && typ != "none" {
		fmt.Printf("Policy  %s every %v days, next %v\n",
			typ, status.Policy["rotation_period_days"], status.Policy["next_rotation_at"])
	} else {
		fmt.Println("Policy  no cadence armed")
	}
	if len(status.Versions) == 0 {
		fmt.Println("No archived versions.")
		return nil
	}
	fmt.Printf("%-10s %-10s %-10s %s\n", "LABEL", "REASON", "OVERLAP", "CREATED")
	for _, v := range status.Versions {
		overlap := v.Overlap
		if overlap == "" {
			overlap = "-"
		}
		fmt.Printf("%-10s %-10s %-10s %s\n", v.Staging, v.Reason, overlap, v.CreatedAt)
	}
	return nil
}

func init() {
	secretsPullCmd.Flags().BoolVarP(&pullForce, "force", "f", false, "Overwrite local changes without prompting")
	secretsPushCmd.Flags().BoolVarP(&pushForce, "force", "f", false, "Push without prompting for missing keys")
	secretsListCmd.Flags().BoolVar(&listRemote, "remote", false, "Fetch latest keys from the cloud instead of local cache")
	secretsSetCmd.Flags().BoolVar(&allEnvs, "all-envs", false, "Set in all three environments simultaneously")
	secretsDiffCmd.Flags().StringVar(&diffFrom, "from", "", "Source environment for cross-environment diff")
	secretsDiffCmd.Flags().StringVar(&diffTo, "to", "", "Target environment for cross-environment diff")

	secretsDeleteCmd.ValidArgsFunction = autocompleteSecretKeys

	_ = secretsDiffCmd.RegisterFlagCompletionFunc("from", autocompleteEnvironments)
	_ = secretsDiffCmd.RegisterFlagCompletionFunc("to", autocompleteEnvironments)

	secretsCmd.AddCommand(
		secretsSetCmd,
		secretsListCmd,
		secretsPullCmd,
		secretsPushCmd,
		secretsDeleteCmd,
		secretsDiffCmd,
		secretsRotateCmd,
		secretsRotationCmd,
	)
	secretsRotationCmd.AddCommand(
		secretsRotationSetCmd,
		secretsRotationStatusCmd,
	)
	secretsRotateCmd.Flags().String("env", "", "environment (development, staging, production)")
	secretsRotateCmd.Flags().String("value", "", "new value inline (prefer --generate or prompt; inline values linger in shell history)")
	secretsRotateCmd.Flags().Bool("generate", false, "generate a random value")
	secretsRotateCmd.Flags().Int("length", 32, "generated value length in bytes")
	secretsRotateCmd.Flags().Bool("promote", false, "promote the staged pending version to current")
	secretsRotateCmd.Flags().Bool("rollback", false, "restore the previous value to current")
	secretsRotateCmd.Flags().Bool("abort", false, "delete the staged pending version")
	secretsRotateCmd.Flags().String("reason", "routine", "routine or compromise (compromise shreds previous immediately)")
	secretsRotateCmd.Flags().String("expected-current", "", "compare-and-swap: only promote if this is still the current version")
	secretsRotateCmd.Flags().Bool("confirm", false, "skip confirmation prompts")
	secretsRotateCmd.ValidArgsFunction = autocompleteSecretKeys
	secretsRotationSetCmd.Flags().String("env", "", "environment (development, staging, production)")
	secretsRotationSetCmd.Flags().String("type", "value_client", "rotation class: value_client, value_auto, or value_provider")
	secretsRotationSetCmd.Flags().Int("period-days", 0, "rotation cadence in days (1-365)")
	secretsRotationSetCmd.Flags().String("adapter", "", "provider adapter for value_provider (currently: postgres)")
	secretsRotationSetCmd.Flags().String("adapter-ref", "", "pinned adapter version <id>@<version>[#sha256:<hex>] (derives --adapter; server backfills bundled version if omitted)")
	secretsRotationSetCmd.Flags().String("admin-credential-ref", "", "secret key of the provider admin credential (same project/environment)")
	secretsRotationSetCmd.Flags().String("target-user", "", "provider-side identity to rotate (e.g. database role)")
	secretsRotationSetCmd.Flags().Int("length-bytes", 0, "minted credential length 16-256 (provider default 32)")
	secretsRotationSetCmd.Flags().Int("overlap-hours", 0, "routine-rotation grace window in hours")
	secretsRotationSetCmd.Flags().Bool("disable", false, "disarm the rotation cadence")
	secretsRotationStatusCmd.Flags().String("env", "", "environment (development, staging, production)")
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
		if !confirmProceed(false, fmt.Sprintf("This will set %s in development, staging, and production. Continue? (y/n): ", strings.Join(keyNames, ", "))) {
			ui.Info("Cancelled.")
			return nil
		}

		if err := verifyPasswordLocally(); err != nil {
			return err
		}

		for _, env := range config.ValidEnvironments {
			if err := ui.Spinner(fmt.Sprintf("Setting in %s...", env), func() error {
				return app.Secrets().BatchSet(kv, env)
			}); err != nil {
				ui.Error(fmt.Sprintf("Failed to set in %s: %v", env, err))
				continue
			}
			ui.Success(fmt.Sprintf("Set in %s", env))
		}
		return nil
	}

	env := config.ResolveEnvironment()
	if env == "production" {
		if err := verifyPasswordLocally(); err != nil {
			return err
		}
	}

	if err := ui.Spinner(fmt.Sprintf("Encrypting and syncing %d secrets...", len(kv)), func() error {
		return app.Secrets().BatchSet(kv, "")
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
	envs := config.ValidEnvironments

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
	envs := config.ValidEnvironments

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
				list, err := app.Secrets().ListForEnv(envName)
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

	// Map of key -> presence flag per environment, indexed by position in
	// config.ValidEnvironments (keeps the table columns and the constant in sync).
	presence := make(map[string][]bool)
	allKeysSet := make(map[string]bool)

	envIndex := make(map[string]int, len(envs))
	for i, e := range envs {
		envIndex[e] = i
	}

	for res := range results {
		idx, ok := envIndex[res.env]
		if !ok {
			continue
		}
		for _, k := range res.keys {
			p := presence[k]
			if p == nil {
				p = make([]bool, len(envs))
			}
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

	fmt.Printf("\nEnvironment: %s\n\n", ui.BrandStyle.Render(activeEnv))
	fmt.Println(renderEnvPresenceTable(envs, presence, allKeysSet))
	fmt.Println()
	return nil
}

// renderEnvPresenceTable renders a "Key | ENV1 | ENV2 | ..." table where each
// cell shows whether the key is present in that environment. Columns follow the
// order of envs; presence[key][i] corresponds to envs[i].
func renderEnvPresenceTable(envs []string, presence map[string][]bool, allKeysSet map[string]bool) string {
	var sortedKeys []string
	for k := range allKeysSet {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	headers := make([]string, 0, len(envs)+1)
	headers = append(headers, "Key")
	for _, e := range envs {
		headers = append(headers, envColumnLabel(e))
	}

	rows := make([][]string, len(sortedKeys))
	for i, k := range sortedKeys {
		row := make([]string, 0, len(envs)+1)
		row = append(row, ui.BrandStyle.Render(k))
		p := presence[k]
		for j := range envs {
			if j < len(p) && p[j] {
				row = append(row, ui.SuccessStyle.Render("*"))
			} else {
				row = append(row, ui.DimStyle.Render("-"))
			}
		}
		rows[i] = row
	}

	return ui.RenderTable(headers, rows)
}

// envColumnLabel returns the short, upper-cased column header for an environment
// name (e.g. "development" -> "DEV", "production" -> "PROD").
func envColumnLabel(env string) string {
	switch env {
	case "development":
		return "DEV"
	case "production":
		return "PROD"
	default:
		return strings.ToUpper(env)
	}
}

func runSecretsPull(cmd *cobra.Command, args []string) error {
	var diff *secrets.DiffResult

	// 1. Check for conflicts first
	if err := ui.Spinner("Checking for conflicts...", func() error {
		var e error
		diff, e = app.Secrets().Diff("", "")
		return e
	}); err != nil {
		ui.Error("Failed to check for conflicts: " + err.Error())
		return nil
	}

	hasConflicts := len(diff.Changed) > 0
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
		if err := app.Secrets().Pull(targetKeys); err != nil {
			return err
		}

		pc, err := config.LoadProjectConfig()
		if err == nil && pc.WorkspaceID != "" {
			domainsResp, err := app.Workspaces().ListAllowlist(pc.WorkspaceID)
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
		diff, e = app.Secrets().Diff("", "")
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
		return app.Secrets().Push()
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
				if err := app.Secrets().Delete(key); err != nil {
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

	project, err := config.LoadProjectConfig()
	if err != nil || project == nil || project.ProjectID == "" {
		return fmt.Errorf("no project configured in current directory")
	}

	env := config.ResolveEnvironment()

	// Check if secret exists locally or remotely first
	exists, err := secretExists(project.ProjectID, env, key)
	if err != nil {
		return err
	}

	if !exists {
		return errors.New(errors.ErrSecretNotFound, fmt.Sprintf("secret %q does not exist in project", key), fmt.Errorf("Please verify the key name or switch environments"))
	}

	// Confirm before deleting from production
	if env == "production" {
		if !confirmProceed(false, fmt.Sprintf("Delete %s from production? (y/n): ", key)) {
			ui.Info("Delete cancelled.")
			return nil
		}
		if err := verifyPasswordLocally(); err != nil {
			return err
		}
	}

	if err := ui.Spinner(fmt.Sprintf("Deleting %s...", key), func() error {
		return app.Secrets().Delete(key)
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
		diff, e = app.Secrets().Diff(diffFrom, diffTo)
		return e
	}); err != nil {
		ui.Error(fmt.Sprintf("Diff: %v", err))
		return nil
	}

	pc, _ := config.LoadProjectConfig()
	var allowlistRemote []workspaces.AllowlistDomain
	var allowlistLocal []string
	if pc != nil && pc.WorkspaceID != "" {
		if remote, err := app.Workspaces().ListAllowlist(pc.WorkspaceID); err == nil {
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

func autocompleteSecretKeys(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	project, err := config.LoadProjectConfig()
	if err != nil || project == nil || project.ProjectID == "" {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	env := config.ResolveEnvironment()
	keys, err := keyring.ListProjectKeyNames(project.ProjectID, env)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	var completions []string
	for _, k := range keys {
		if strings.HasPrefix(strings.ToLower(k), strings.ToLower(toComplete)) {
			completions = append(completions, k)
		}
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}
