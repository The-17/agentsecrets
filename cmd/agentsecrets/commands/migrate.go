package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/migration"
	"github.com/The-17/agentsecrets/pkg/ui"
)

// migrate flags. The token flag is shared by the pull (`migrate --from`) and
// export (`migrate export`) forms because both consume the same single-use
// credential; it is only bound once per command, so cobra stays happy.
var (
	migrateFrom   string
	migrateToken  string
	migrateOutput string
	migrateFile   string
	migrateJSON   bool
	migrateYes    bool
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Move your account, workspaces, and secrets between servers",
	Long: `Move your AgentSecrets data between server instances.

Works with any combination of AgentSecrets Cloud and a self-hosted server, in
either direction. Your secrets stay end-to-end encrypted: the servers move the
ciphertexts, never the plaintext, and your private key is carried across so the
same master password keeps working.

Pull mode (destination talks to the source):
  1. On the source:      agentsecrets server set <source> && agentsecrets login
                         agentsecrets migrate token
  2. On the destination: agentsecrets server set <destination> && agentsecrets login
                         agentsecrets migrate --from <source> --token <TOKEN>

Offline mode (no direct server-to-server reachability) uses a bundle file:
  agentsecrets migrate export --output bundle.json   # on the source
  agentsecrets migrate import bundle.json            # on the destination`,
	Example: `  # Mint a single-use token on the server that holds your data
  agentsecrets migrate token

  # Pull that data onto the server you are signed in to
  agentsecrets migrate --from https://api.agentsecrets.tech --token eyJ...

  # Airgapped: export to a file, carry it, then import
  agentsecrets migrate export --output bundle.json
  agentsecrets migrate import bundle.json`,
	RunE: runMigratePull,
}

var migrateTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Mint a single-use migration token on the current server",
	Long: `Generate a signed migration token for the account you are signed in with.

The token is valid for 30 minutes and can be used once. Treat it like a
password: anyone who holds it can export your account's data.`,
	RunE: runMigrateToken,
}

var migrateExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export your data from the current server to a portable bundle",
	Long: `Export your workspaces, projects, secrets, agents, and account keys to a
JSON bundle.

Use this for airgapped moves, or to keep a copy before a large change. The
bundle contains your encrypted key material and password hash, so treat the
file as sensitive: it is written with owner-only (0600) permissions.`,
	RunE: runMigrateExport,
}

var migrateImportCmd = &cobra.Command{
	Use:   "import [bundle.json]",
	Short: "Import a portable bundle into the current server",
	Long: `Import a bundle produced by 'agentsecrets migrate export' into the server you
are currently signed in to.

Use '-' to read the bundle from stdin. Import is additive and idempotent:
existing records with the same IDs are updated, not duplicated.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runMigrateImport,
}

func init() {
	migrateCmd.Flags().StringVar(&migrateFrom, "from", "", "Source server base URL, e.g. https://api.agentsecrets.tech (no /api suffix)")
	migrateCmd.Flags().StringVar(&migrateToken, "token", "", "Migration token minted on the source with 'agentsecrets migrate token'")

	migrateTokenCmd.Flags().BoolVar(&migrateJSON, "json", false, "Print the token as JSON for scripts")

	migrateExportCmd.Flags().StringVarP(&migrateOutput, "output", "o", "", "File to write the bundle to ('-' for stdout; default agentsecrets-migration-<timestamp>.json)")
	migrateExportCmd.Flags().StringVar(&migrateToken, "token", "", "Reuse an existing migration token instead of minting one")

	migrateImportCmd.Flags().StringVar(&migrateFile, "file", "", "Bundle file to import (alternative to the positional argument)")
	migrateImportCmd.Flags().BoolVarP(&migrateYes, "yes", "y", false, "Skip the confirmation prompt")

	migrateCmd.AddCommand(migrateTokenCmd, migrateExportCmd, migrateImportCmd)
}

// runMigratePull imports data into the current server by asking it to fetch the
// bundle straight from the source.
func runMigratePull(cmd *cobra.Command, args []string) error {
	if migrateFrom == "" || migrateToken == "" {
		return fmt.Errorf("--from and --token are both required (run 'agentsecrets migrate --help')")
	}

	source := normalizeMigrationSource(migrateFrom)
	svc := migration.NewService(app.API())

	ui.Info(fmt.Sprintf("Pulling your data from %s", source))
	var result *migration.ImportResult
	if err := ui.Spinner("Requesting the migration bundle...", func() error {
		var err error
		result, err = svc.ImportFromSource(source, migrateToken)
		return err
	}); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	printMigrationSummary(result)
	return nil
}

// runMigrateToken mints a migration token on the current server.
func runMigrateToken(cmd *cobra.Command, args []string) error {
	svc := migration.NewService(app.API())

	var tok *migration.Token
	if err := ui.Spinner("Generating a migration token...", func() error {
		var err error
		tok, err = svc.CreateToken()
		return err
	}); err != nil {
		return fmt.Errorf("migrate token: %w", err)
	}

	if migrateJSON {
		out, err := json.MarshalIndent(tok, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}

	fmt.Println()
	ui.Success("Migration token generated")
	ui.StatusRow("Token", tok.Token)
	ui.StatusRow("Expires", tok.ExpiresAt)
	ui.StatusRow("Account", tok.UserEmail)
	ui.StatusRow("Workspaces", strconv.Itoa(tok.WorkspaceCount))
	fmt.Println()
	ui.Info("Single-use, valid for 30 minutes. Mint a fresh token for each migration.")
	ui.Info("On the other server run: agentsecrets migrate --from " + config.GetServerURL() + " --token <token>")
	return nil
}

// runMigrateExport writes a portable bundle to a file (or stdout).
func runMigrateExport(cmd *cobra.Command, args []string) error {
	svc := migration.NewService(app.API())

	token := migrateToken
	if token == "" {
		var tok *migration.Token
		if err := ui.Spinner("Generating a migration token...", func() error {
			var err error
			tok, err = svc.CreateToken()
			return err
		}); err != nil {
			return fmt.Errorf("migrate export: %w", err)
		}
		token = tok.Token
	}

	var bundle migration.Bundle
	if err := ui.Spinner("Exporting your data...", func() error {
		var err error
		bundle, err = svc.Export(token)
		return err
	}); err != nil {
		return fmt.Errorf("migrate export: %w", err)
	}
	if len(bundle) == 0 {
		return fmt.Errorf("migrate export: server returned an empty bundle")
	}

	out := migrateOutput
	if out == "" {
		out = fmt.Sprintf("agentsecrets-migration-%s.json", time.Now().UTC().Format("20060102-150405"))
	}
	if out == "-" {
		if _, err := os.Stdout.Write(bundle); err != nil {
			return fmt.Errorf("write bundle to stdout: %w", err)
		}
		fmt.Fprintln(os.Stdout)
		return nil
	}
	if err := os.WriteFile(out, bundle, 0600); err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}

	meta := summariseBundle(bundle)
	fmt.Println()
	ui.Success("Export complete")
	ui.StatusRow("File", out)
	if meta.Email != "" {
		ui.StatusRow("Account", meta.Email)
	}
	ui.StatusRow("Workspaces", strconv.Itoa(meta.Workspaces))
	ui.StatusRow("Projects", strconv.Itoa(meta.Projects))
	ui.StatusRow("Secrets", strconv.Itoa(meta.Secrets))
	fmt.Println()
	ui.Warning("This file holds your encrypted keys and password hash. Keep it private and delete it after the move.")
	return nil
}

// runMigrateImport reads a bundle file and imports it into the current server.
func runMigrateImport(cmd *cobra.Command, args []string) error {
	path := migrateFile
	if len(args) == 1 {
		path = args[0]
	}
	if path == "" {
		return fmt.Errorf("provide a bundle file: 'agentsecrets migrate import <file>' (use '-' for stdin)")
	}

	raw, err := readBundle(path)
	if err != nil {
		return err
	}
	if !json.Valid(raw) {
		return fmt.Errorf("%s is not valid JSON — expected a bundle from 'agentsecrets migrate export'", path)
	}

	target := config.GetServerURL()
	if !confirmProceed(migrateYes, fmt.Sprintf("Import the bundle into %s? [y/N] ", target)) {
		ui.Info("Aborted.")
		return nil
	}

	svc := migration.NewService(app.API())
	var result *migration.ImportResult
	if err := ui.Spinner("Importing the migration bundle...", func() error {
		var err error
		result, err = svc.ImportBundle(raw)
		return err
	}); err != nil {
		return fmt.Errorf("migrate import: %w", err)
	}

	printMigrationSummary(result)
	return nil
}

// readBundle loads a bundle from a file path, or from stdin when path is "-".
func readBundle(path string) ([]byte, error) {
	if path == "-" {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read bundle from stdin: %w", err)
		}
		return raw, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	return raw, nil
}

// normalizeMigrationSource reduces any accepted server spelling to the bare
// base URL the destination server expects. The import route appends
// '/api/migration/export/' itself, so a stored '/api' suffix must be dropped or
// the fetch would hit '/api/api/migration/export/'.
func normalizeMigrationSource(raw string) string {
	norm := config.NormalizeServerURL(raw)
	return strings.TrimSuffix(strings.TrimRight(norm, "/"), "/api")
}

// bundleMeta is the small, non-secret slice of a bundle used for the export
// summary. It deliberately ignores secret values and key material.
type bundleMeta struct {
	Email      string
	Workspaces int
	Projects   int
	Secrets    int
}

func summariseBundle(raw []byte) bundleMeta {
	var doc struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
		Workspaces []struct {
			Projects []struct {
				Secrets []json.RawMessage `json:"secrets"`
			} `json:"projects"`
		} `json:"workspaces"`
	}
	_ = json.Unmarshal(raw, &doc)

	meta := bundleMeta{Email: doc.User.Email, Workspaces: len(doc.Workspaces)}
	for _, ws := range doc.Workspaces {
		meta.Projects += len(ws.Projects)
		for _, proj := range ws.Projects {
			meta.Secrets += len(proj.Secrets)
		}
	}
	return meta
}

func printMigrationSummary(result *migration.ImportResult) {
	if result == nil {
		return
	}
	fmt.Println()
	ui.Success("Migration complete")
	ui.StatusRow("Account", result.UserEmail)
	ui.StatusRow("Workspaces", strconv.Itoa(result.Summary.WorkspacesImported))
	ui.StatusRow("Projects", strconv.Itoa(result.Summary.ProjectsImported))
	ui.StatusRow("Secrets", strconv.Itoa(result.Summary.SecretsImported))
	ui.StatusRow("Agents", strconv.Itoa(result.Summary.AgentsImported))
	ui.StatusRow("Allowlist entries", strconv.Itoa(result.Summary.AllowlistEntriesImported))
	fmt.Println()
	ui.Info("Your secrets keep their client-side encryption — sign in with the same master password to read them.")
}
