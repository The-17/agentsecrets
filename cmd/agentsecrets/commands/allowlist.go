package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/The-17/agentsecrets/pkg/workspaces"
)

var workspaceAllowlistCmd = &cobra.Command{
	Use:   "allowlist",
	Short: "Manage workspace domain allowlist",
	Long:  `Manage the allowed domains for the proxy. The proxy will block credential injection to any domain not in this list.`,
}

var allowlistAddCmd = &cobra.Command{
	Use:   "add <domain> [domain...] | --secret KEY [--secret KEY...]",
	Short: "Add one or more domains to the allowlist",
	Long: `Add domains to the workspace allowlist.

A domain can be given directly, or named by the secret whose value is that
domain. Use --secret when the value itself is sensitive: it is derived and
added without ever being printed.`,
	Args: cobra.ArbitraryArgs,
	RunE: runAllowlistAdd,
}

// allowlistSecretKeys names secrets whose values are domains to allowlist. The
// value never needs to reach the terminal: the user knows the key, and the CLI
// already holds the value in memory.
var allowlistSecretKeys []string

var allowlistRemoveCmd = &cobra.Command{
	Use:   "remove <domain>",
	Short: "Remove a domain from the allowlist",
	Args:  cobra.ExactArgs(1),
	RunE:  runAllowlistRemove,
}

var allowlistListCmd = &cobra.Command{
	Use:   "list",
	Short: "List allowed domains",
	RunE:  runAllowlistList,
}

var allowlistLogCmd = &cobra.Command{
	Use:   "logs",
	Short: "View allowlist audit logs",
	RunE:  runAllowlistLog,
}

func init() {
	allowlistRemoveCmd.ValidArgsFunction = autocompleteAllowlistDomains
	allowlistAddCmd.Flags().StringArrayVar(&allowlistSecretKeys, "secret", nil,
		"Add the host named by this secret key instead of pasting the value (repeatable)")

	workspaceAllowlistCmd.AddCommand(
		allowlistAddCmd,
		allowlistRemoveCmd,
		allowlistListCmd,
		allowlistLogCmd,
	)
	workspaceCmd.AddCommand(workspaceAllowlistCmd)
}

func verifyPasswordLocally() error {
	cfg, err := config.LoadGlobalConfig()
	if err != nil || cfg.Email == "" {
		return fmt.Errorf("Not logged in.")
	}

	if cfg.PasswordHash == "" {
		return fmt.Errorf("Please run 'agentsecrets login' once to enable secure local password verification for allowlist modifications.")
	}

	fmt.Print("Enter your AgentSecrets password: ")
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println() // newline after hidden input
	password := string(passwordBytes)

	hasher := sha256.New()
	hasher.Write([]byte(cfg.Email + ":" + password))
	inputHash := hex.EncodeToString(hasher.Sum(nil))

	if inputHash != cfg.PasswordHash {
		// Output manually to bypass cobra's default error formatting slightly if needed,
		// or just return the error.
		return fmt.Errorf("Incorrect password")
	}

	return nil
}

func syncAllowlistToKeyring(workspaceID string) error {
	domainsResp, err := app.Workspaces().ListAllowlist(workspaceID)
	if err != nil {
		return err
	}
	var domains []string
	for _, d := range domainsResp {
		domains = append(domains, d.Domain)
	}
	return keyring.SetWorkspaceAllowlist(workspaceID, domains)
}

func runAllowlistAdd(_ *cobra.Command, args []string) error {
	domains := args

	if len(allowlistSecretKeys) > 0 && len(args) > 0 {
		return fmt.Errorf("give either host arguments or --secret, not both: a host named by a secret is added from the secret itself")
	}
	if len(allowlistSecretKeys) == 0 && len(args) == 0 {
		return fmt.Errorf("nothing to add. Give a host, or --secret KEY to add the host named by a secret")
	}

	fromSecrets := len(allowlistSecretKeys) > 0
	if fromSecrets {
		derived, err := hostsFromSecretKeys(allowlistSecretKeys)
		if err != nil {
			return err
		}
		domains = derived
	}

	workspaceID, err := requireWorkspace()
	if err != nil {
		return err
	}

	if err := verifyPasswordLocally(); err != nil {
		return err
	}

	subject := strings.Join(domains, ", ")
	if fromSecrets {
		// The derived host can be the secret itself. Name the secret, not the host.
		subject = fmt.Sprintf("the host named by %s", strings.Join(allowlistSecretKeys, ", "))
	}

	var opErr error
	if err := ui.Spinner(fmt.Sprintf("Adding %s to allowlist...", subject), func() error {
		if err := app.Workspaces().AddAllowlist(workspaceID, domains...); err != nil {
			if strings.Contains(err.Error(), "403") {
				return fmt.Errorf("Only workspace admins can modify the allowlist.")
			}
			return err
		}
		return syncAllowlistToKeyring(workspaceID)
	}); err != nil {
		opErr = err
	}

	if opErr != nil {
		return opErr
	}

	cfg, _ := config.LoadGlobalConfig()
	wsName := cfg.Workspaces[workspaceID].Name
	if fromSecrets {
		ui.Success(fmt.Sprintf("%d host(s) named by %s added to %s allowlist", len(domains), strings.Join(allowlistSecretKeys, ", "), wsName))
	} else {
		ui.Success(fmt.Sprintf("%s added to %s allowlist", strings.Join(domains, ", "), wsName))
	}

	projectID := currentProjectID()
	if fromSecrets {
		_ = proxy.LogManagementEvent("ADD", "allowlist", fmt.Sprintf("Added host(s) named by %s", strings.Join(allowlistSecretKeys, ", ")), cfg.Email, workspaceID, projectID, config.ResolveEnvironment())
		return nil
	}
	for _, d := range domains {
		_ = proxy.LogManagementEvent("ADD", "allowlist", fmt.Sprintf("Added domain %s", d), cfg.Email, workspaceID, projectID, config.ResolveEnvironment())
	}

	return nil
}

// hostsFromSecretKeys derives the hosts named by the given secrets in the active
// project and environment. It exists so an allowlist entry whose value is
// sensitive can be added by key name instead of by pasting the value.
func hostsFromSecretKeys(keys []string) ([]string, error) {
	project, err := config.LoadProjectConfig()
	if err != nil || project == nil || project.ProjectID == "" {
		return nil, fmt.Errorf("no active project. Run: agentsecrets project use <name>")
	}
	if err := ensureKeychainAuthForEnv(); err != nil {
		return nil, err
	}
	all, err := keyring.GetAllProjectSecrets(project.ProjectID, config.ResolveEnvironment())
	if err != nil {
		return nil, fmt.Errorf("failed to load secrets from keychain: %w", err)
	}

	chosen := map[string]string{}
	var missing []string
	for _, k := range keys {
		if v, ok := all[k]; ok {
			chosen[k] = v
		} else {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, errors.New(errors.ErrSecretNotFound,
			fmt.Sprintf("no secret named %s in this project", strings.Join(missing, ", ")),
			fmt.Errorf("check the key name and the active environment (%s), or run 'agentsecrets secrets list'", config.ResolveEnvironment()))
	}

	hosts := hostsFromSecrets(chosen)
	if len(hosts) == 0 {
		return nil, errors.New(errors.ErrSecretNotFound,
			fmt.Sprintf("no host found in the value of %s", strings.Join(keys, ", ")),
			fmt.Errorf("the value has to be a URL, a host, or a host:port for the allowlist entry to be derived from it"))
	}
	return hosts, nil
}

func runAllowlistRemove(_ *cobra.Command, args []string) error {
	domain := args[0]

	workspaceID, err := requireWorkspace()
	if err != nil {
		return err
	}

	// Validate that the domain actually exists in the allowlist first
	allowlist, alErr := keyring.GetWorkspaceAllowlist(workspaceID)
	if alErr == nil && len(allowlist) > 0 {
		found := false
		for _, d := range allowlist {
			if strings.EqualFold(d, domain) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s is not in the allowlist.", domain)
		}
	}

	if err := verifyPasswordLocally(); err != nil {
		return err
	}

	var opErr error
	if err := ui.Spinner(fmt.Sprintf("Removing %s from allowlist...", domain), func() error {
		if err := app.Workspaces().RemoveAllowlist(workspaceID, domain); err != nil {
			if strings.Contains(err.Error(), "403") {
				return fmt.Errorf("Only workspace admins can modify the allowlist.")
			}
			if strings.Contains(err.Error(), "404") {
				return fmt.Errorf("%s is not in the allowlist.", domain)
			}
			return err
		}
		return syncAllowlistToKeyring(workspaceID)
	}); err != nil {
		opErr = err
	}

	if opErr != nil {
		return opErr
	}

	cfg, _ := config.LoadGlobalConfig()
	wsName := cfg.Workspaces[workspaceID].Name
	ui.Success(fmt.Sprintf("%s removed from %s allowlist", domain, wsName))

	projectID := currentProjectID()
	_ = proxy.LogManagementEvent("REMOVE", "allowlist", fmt.Sprintf("Removed domain %s", domain), cfg.Email, workspaceID, projectID, config.ResolveEnvironment())

	return nil
}

func runAllowlistList(_ *cobra.Command, _ []string) error {
	workspaceID, err := requireWorkspace()
	if err != nil {
		return err
	}

	var domainsResp []workspaces.AllowlistDomain
	if err := ui.Spinner("Fetching allowlist...", func() error {
		d, e := app.Workspaces().ListAllowlist(workspaceID)
		domainsResp = d
		return e
	}); err != nil {
		return err
	}

	if len(domainsResp) == 0 {
		ui.Info("No domains in allowlist. Run: agentsecrets workspace allowlist add <domain>")
		return nil
	}

	headers := []string{"Domain", "Added By", "Added At"}
	rows := make([][]string, len(domainsResp))
	for i, d := range domainsResp {
		timeStr := strings.Replace(d.CreatedAt, "T", " ", 1)
		if len(timeStr) > 16 {
			timeStr = timeStr[:16]
		}

		rows[i] = []string{
			d.Domain,
			ui.DimStyle.Render(d.AddedBy),
			ui.DimStyle.Render(timeStr),
		}
	}

	renderedTable := ui.RenderTable(headers, rows)
	fmt.Printf("\n%s\n%s\n\n", ui.BannerStr("Workspace Allowlist"), renderedTable)
	return nil
}

func runAllowlistLog(_ *cobra.Command, _ []string) error {
	workspaceID, err := requireWorkspace()
	if err != nil {
		return err
	}

	var logResp []workspaces.AllowlistLogEntry
	if err := ui.Spinner("Fetching allowlist logs...", func() error {
		l, e := app.Workspaces().LogAllowlist(workspaceID)
		logResp = l
		return e
	}); err != nil {
		return err
	}

	if len(logResp) == 0 {
		ui.Info("No allowlist activity found.")
		return nil
	}

	headers := []string{"Time", "Domain", "User", "Action"}
	rows := make([][]string, len(logResp))
	for i, l := range logResp {
		timeStr := strings.Replace(l.CreatedAt, "T", " ", 1)
		if len(timeStr) > 16 {
			timeStr = timeStr[:16]
		}

		actionStr := l.Action
		if actionStr == "ADDED" {
			actionStr = ui.SuccessStyle.Render(actionStr)
		} else if actionStr == "REMOVED" {
			actionStr = ui.ErrorStyle.Render(actionStr)
		}

		rows[i] = []string{
			ui.DimStyle.Render(timeStr),
			l.Domain,
			ui.DimStyle.Render(l.UserEmail),
			actionStr,
		}
	}

	renderedTable := ui.RenderTable(headers, rows)
	fmt.Printf("\n%s\n%s\n\n", ui.BannerStr("Allowlist Logs"), renderedTable)
	return nil
}

func autocompleteAllowlistDomains(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	workspaceID := config.GetSelectedWorkspaceID()
	if workspaceID == "" {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	domains, err := keyring.GetWorkspaceAllowlist(workspaceID)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var completions []string
	for _, d := range domains {
		if strings.HasPrefix(strings.ToLower(d), strings.ToLower(toComplete)) {
			completions = append(completions, d)
		}
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}
