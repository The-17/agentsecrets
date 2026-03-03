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
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/The-17/agentsecrets/pkg/workspaces"
)

var workspaceAllowlistCmd = &cobra.Command{
	Use:   "allowlist",
	Short: "Manage workspace domain allowlist",
	Long:  `Manage the allowed domains for the proxy. The proxy will block credential injection to any domain not in this list.`,
}

var allowlistAddCmd = &cobra.Command{
	Use:   "add <domain>",
	Short: "Add a domain to the allowlist",
	Args:  cobra.ExactArgs(1),
	RunE:  runAllowlistAdd,
}

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
	Use:   "log",
	Short: "View allowlist audit log",
	RunE:  runAllowlistLog,
}

func init() {
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
	domainsResp, err := workspaceService.ListAllowlist(workspaceID)
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
	domain := args[0]

	workspaceID, err := requireWorkspaceID()
	if err != nil {
		return err
	}

	if err := verifyPasswordLocally(); err != nil {
		return err
	}

	var opErr error
	if err := ui.Spinner(fmt.Sprintf("Adding %s to allowlist...", domain), func() error {
		if err := workspaceService.AddAllowlist(workspaceID, domain); err != nil {
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
	ui.Success(fmt.Sprintf("✓ %s added to %s allowlist", domain, wsName))
	return nil
}

func runAllowlistRemove(_ *cobra.Command, args []string) error {
	domain := args[0]

	workspaceID, err := requireWorkspaceID()
	if err != nil {
		return err
	}

	if err := verifyPasswordLocally(); err != nil {
		return err
	}

	var opErr error
	if err := ui.Spinner(fmt.Sprintf("Removing %s from allowlist...", domain), func() error {
		if err := workspaceService.RemoveAllowlist(workspaceID, domain); err != nil {
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
	ui.Success(fmt.Sprintf("✓ %s removed from %s allowlist", domain, wsName))
	return nil
}

func runAllowlistList(_ *cobra.Command, _ []string) error {
	workspaceID, err := requireWorkspaceID()
	if err != nil {
		return err
	}

	var domainsResp []workspaces.AllowlistDomain
	if err := ui.Spinner("Fetching allowlist...", func() error {
		d, e := workspaceService.ListAllowlist(workspaceID)
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
		// Formatting Time: The spec shows '2026-03-01 14:23'. 
		// Assuming CreatedAt is ISO8601, we might need to substring or parse it. 
		// Given simplicity, we'll assume it's roughly fine or we can substring to 16 chars if it's "YYYY-MM-DDTHH:MM:SSZ"
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
	workspaceID, err := requireWorkspaceID()
	if err != nil {
		return err
	}

	var logResp []workspaces.AllowlistLogEntry
	if err := ui.Spinner("Fetching allowlist logs...", func() error {
		l, e := workspaceService.LogAllowlist(workspaceID)
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
