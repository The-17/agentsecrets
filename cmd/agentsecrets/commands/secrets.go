package commands

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/secrets"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var (
	secretsService *secrets.Service
	pullForce      bool
	pushForce      bool
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

var secretsGetCmd = &cobra.Command{
	Use:   "get [key]",
	Short: "Retrieve and decrypt a single secret",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsGet,
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

	secretsCmd.AddCommand(
		secretsSetCmd,
		secretsGetCmd,
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

	if err := ui.Spinner(fmt.Sprintf("Encrypting and syncing %d secrets...", len(kv)), func() error {
		return secretsService.BatchSet(kv)
	}); err != nil {
		ui.Error(fmt.Sprintf("Failed to set secrets: %v", err))
		return nil
	}

	for k := range kv {
		ui.Success(fmt.Sprintf("Set %s", k))
	}
	return nil
}

func runSecretsGet(cmd *cobra.Command, args []string) error {
	key := args[0]

	if err := ui.Spinner(fmt.Sprintf("Retrieving %s...", key), func() error {
		_, e := secretsService.Get(key)
		return e
	}); err != nil {
		ui.Error(fmt.Sprintf("Get secret: %v", err))
		return nil
	}

	fmt.Printf("\n%s\n", ui.BrandStyle.Render(key))
	return nil
}

func runSecretsList(cmd *cobra.Command, args []string) error {
	var list []secrets.SecretMetadata

	if err := ui.Spinner("Fetching keys...", func() error {
		var e error
		list, e = secretsService.List(false)
		return e
	}); err != nil {
		ui.Error(fmt.Sprintf("List secrets: %v", err))
		return nil
	}

	if len(list) == 0 {
		ui.Info("No secrets found in this project. Use 'agentsecrets secrets set KEY=VALUE' to add one.")
		return nil
	}

	headers := []string{"Key"}

	rows := make([][]string, len(list))
	for i, s := range list {
		rows[i] = []string{ui.BrandStyle.Render(s.Key)}
	}

	renderedTable := ui.RenderTable(headers, rows)
	fmt.Printf("\n%s\n%s\n\n", ui.BannerStr("Project Secrets"), renderedTable)
	return nil
}

func runSecretsPull(cmd *cobra.Command, args []string) error {
	var diff *secrets.DiffResult

	// 1. Check for conflicts first
	if err := ui.Spinner("Checking for conflicts...", func() error {
		var e error
		diff, e = secretsService.Diff()
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

	if err := ui.Spinner(fmt.Sprintf("Pulling %d secrets...", pullCount), func() error {
		return secretsService.Pull(targetKeys)
	}); err != nil {
		ui.Error(fmt.Sprintf("Pull: %v", err))
		return nil
	}

	ui.Success("Successfully synced cloud secrets.")
	return nil
}

func runSecretsPush(cmd *cobra.Command, args []string) error {
	// 1. Check for keys in cloud that are missing locally
	var diff *secrets.DiffResult

	if err := ui.Spinner("Checking for conflicts...", func() error {
		var e error
		diff, e = secretsService.Diff()
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
		ui.Error(fmt.Sprintf("Push: %v", err))
		return nil
	}

	ui.Success("Successfully pushed .env secrets to the cloud.")

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

	if err := ui.Spinner("Comparing secrets...", func() error {
		var e error
		diff, e = secretsService.Diff()
		return e
	}); err != nil {
		ui.Error(fmt.Sprintf("Diff: %v", err))
		return nil
	}

	fmt.Printf("\n%s\n", ui.BannerStr("Secret Diff"))

	if len(diff.Added) == 0 && len(diff.Removed) == 0 && len(diff.Changed) == 0 {
		ui.Success("Local and cloud secrets are in sync!")
		return nil
	}

	for _, k := range diff.Added {
		fmt.Printf("  %s %s %s\n", ui.SuccessStyle.Render("+"), ui.BrandStyle.Render(k), ui.DimStyle.Render("(new)"))
	}
	for _, k := range diff.Removed {
		fmt.Printf("  %s %s %s\n", ui.ErrorStyle.Render("-"), ui.BrandStyle.Render(k), ui.DimStyle.Render("(missing locally)"))
	}
	for k := range diff.Changed {
		fmt.Printf("  %s %s %s\n", ui.LabelStyle.Render("~"), ui.BrandStyle.Render(k), ui.DimStyle.Render("(mismatch)"))
	}
	fmt.Println()

	return nil
}

