package commands

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/huh/spinner"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/secrets"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var (
	secretsService *secrets.Service
	pullForce      bool
	showValue      bool
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
	secretsListCmd.Flags().BoolVarP(&showValue, "value", "v", false, "Decrypt and show secret values")
	secretsGetCmd.Flags().BoolVarP(&showValue, "value", "v", false, "Decrypt and show the secret value")

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

	var setErr error
	err := spinner.New().
		Title(fmt.Sprintf("Encrypting and syncing %d secrets...", len(kv))).
		Action(func() {
			setErr = secretsService.BatchSet(kv)
		}).
		Run()

	if err != nil {
		return err
	}
	if setErr != nil {
		ui.Error(fmt.Sprintf("Failed to set secrets: %v", setErr))
		return nil
	}

	for k := range kv {
		ui.Success(fmt.Sprintf("Set %s", k))
	}
	return nil
}

func runSecretsGet(cmd *cobra.Command, args []string) error {
	key := args[0]
	var value string
	var getErr error

	err := spinner.New().
		Title(fmt.Sprintf("Retrieving %s...", key)).
		Action(func() {
			value, getErr = secretsService.Get(key)
		}).
		Run()

	if err != nil {
		return err
	}
	if getErr != nil {
		ui.Error(fmt.Sprintf("Failed to get secret: %v", getErr))
		return nil
	}

	if showValue {
		fmt.Printf("\n%s=%s\n", ui.BrandStyle.Render(key), value)
	} else {
		fmt.Printf("\n%s\n", ui.BrandStyle.Render(key))
	}
	return nil
}

func runSecretsList(cmd *cobra.Command, args []string) error {
	var list []secrets.SecretMetadata
	var listErr error

	err := spinner.New().
		Title(fmt.Sprintf("Fetching secret keys%s...", func() string {
			if showValue {
				return " and values"
			}
			return ""
		}())).
		Action(func() {
			list, listErr = secretsService.List(showValue)
		}).
		Run()

	if err != nil {
		return err
	}
	if listErr != nil {
		ui.Error("Failed to list secrets: " + listErr.Error())
		return nil
	}

	if len(list) == 0 {
		ui.Info("No secrets found in this project. Use 'agentsecrets secrets set KEY=VALUE' to add one.")
		return nil
	}

	headers := []string{"Key"}
	if showValue {
		headers = append(headers, "Value")
	}

	rows := make([][]string, len(list))
	for i, s := range list {
		row := []string{ui.BrandStyle.Render(s.Key)}
		if showValue {
			row = append(row, s.Value)
		}
		rows[i] = row
	}

	renderedTable := ui.RenderTable(headers, rows)
	fmt.Println()
	fmt.Println(ui.BannerStr("Project Secrets"))
	fmt.Println(renderedTable)
	fmt.Println()

	return nil
}

func runSecretsPull(cmd *cobra.Command, args []string) error {
	var diff *secrets.DiffResult
	var diffErr error

	// 1. Check for conflicts first
	err := spinner.New().
		Title("Checking for conflicts...").
		Action(func() {
			diff, diffErr = secretsService.Diff()
		}).
		Run()

	if err != nil {
		return err
	}
	if diffErr != nil {
		ui.Error("Failed to check for conflicts: " + diffErr.Error())
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
			// We only want to pull keys that are in cloud but NOT in local (diff.Removed)
			if len(diff.Removed) == 0 {
				ui.Info("No missing secrets found. Pull cancelled (local changes preserved).")
				return nil
			}
			targetKeys = diff.Removed
			if targetKeys == nil {
				targetKeys = []string{} // Should not happen with len check but safe
			}
		case "overwrite":
			targetKeys = nil // Pull all
		}
	}

	var pullErr error
	err = spinner.New().
		Title(fmt.Sprintf("Smart Pulling %d secrets...", func() int {
			if targetKeys == nil {
				return len(diff.Removed) + len(diff.Changed) + len(diff.Unchanged)
			}
			return len(targetKeys)
		}())).
		Action(func() {
			pullErr = secretsService.Pull(targetKeys)
		}).
		Run()

	if err != nil {
		return err
	}
	if pullErr != nil {
		ui.Error("Failed to pull secrets: " + pullErr.Error())
		return nil
	}

	ui.Success("Successfully synced cloud secrets.")
	return nil
}

func runSecretsPush(cmd *cobra.Command, args []string) error {
	var pushErr error
	err := spinner.New().
		Title("Encrypting and pushing local secrets...").
		Action(func() {
			pushErr = secretsService.Push()
		}).
		Run()

	if err != nil {
		return err
	}
	if pushErr != nil {
		ui.Error("Failed to push secrets: " + pushErr.Error())
		return nil
	}

	ui.Success("Successfully pushed .env secrets to the cloud.")
	return nil
}

func runSecretsDelete(cmd *cobra.Command, args []string) error {
	key := args[0]
	var delErr error

	err := spinner.New().
		Title(fmt.Sprintf("Deleting %s...", key)).
		Action(func() {
			delErr = secretsService.Delete(key)
		}).
		Run()

	if err != nil {
		return err
	}
	if delErr != nil {
		ui.Error("Failed to delete secret: " + delErr.Error())
		return nil
	}

	ui.Success(fmt.Sprintf("Deleted %s from cloud and local files.", key))
	return nil
}

func runSecretsDiff(cmd *cobra.Command, args []string) error {
	var diff *secrets.DiffResult
	var diffErr error

	err := spinner.New().
		Title("Comparing local and cloud secrets...").
		Action(func() {
			diff, diffErr = secretsService.Diff()
		}).
		Run()

	if err != nil {
		return err
	}
	if diffErr != nil {
		ui.Error("Failed to diff secrets: " + diffErr.Error())
		return nil
	}

	fmt.Println()
	fmt.Println(ui.BannerStr("Secret Diff"))

	if len(diff.Added) == 0 && len(diff.Removed) == 0 && len(diff.Changed) == 0 {
		ui.Success("Local and cloud secrets are in sync!")
		return nil
	}

	for _, k := range diff.Added {
		fmt.Printf("  %s %s %s\n", ui.SuccessStyle.Render("+"), ui.BrandStyle.Render(k), ui.DimStyle.Render("(new local)"))
	}
	for _, k := range diff.Removed {
		fmt.Printf("  %s %s %s\n", ui.ErrorStyle.Render("-"), ui.BrandStyle.Render(k), ui.DimStyle.Render("(not found locally)"))
	}
	for k := range diff.Changed {
		fmt.Printf("  %s %s %s\n", ui.LabelStyle.Render("~"), ui.BrandStyle.Render(k), ui.DimStyle.Render("(value mismatch)"))
	}
	fmt.Println()

	return nil
}
