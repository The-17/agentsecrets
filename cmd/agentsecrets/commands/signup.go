package commands

import (
	"fmt"
	"os"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/The-17/agentsecrets/pkg/config"
)

var signupServerFlag string

var signupCmd = &cobra.Command{
	Use:   "signup",
	Short: "Create a new AgentSecrets account",
	Long: `Create a new AgentSecrets account.

	Choose email and password, Google, or GitHub. The email path generates your
	encryption keypair and shows the recovery key once. A social sign-up creates
	the account, signs you in, and asks you to choose a vault password so your
	secrets are protected on this device right away.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if signupServerFlag != "" {
			if err := config.SetGlobalServerURL(signupServerFlag); err != nil {
				return fmt.Errorf("invalid server URL: %w", err)
			}
		}
		if !config.GlobalConfigExists() {
			if err := config.InitGlobalConfig(); err != nil {
				return fmt.Errorf("failed to initialize global config: %w", err)
			}
			_ = config.SetSelectedEnvironment("development")
		}

		var choice string
		err := huh.NewSelect[string]().
			Title("How would you like to create your account?").
			Options(
				huh.NewOption("Email and password", "password"),
				huh.NewOption("Continue with Google", "google"),
				huh.NewOption("Continue with GitHub", "github"),
			).
			Value(&choice).
			Run()
		if err != nil {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return fmt.Errorf("signup needs a terminal to choose a method")
			}
			return nil // cancelled
		}

		fmt.Println()
		switch choice {
		case "google":
			return performOAuth("google")
		case "github":
			return performOAuth("github")
		default:
			return runSignup()
		}
	},
}

func init() {
	signupCmd.Flags().StringVar(&signupServerFlag, "server", "", "Target AgentSecrets server URL")
}
