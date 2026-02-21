package commands

import (
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/huh/spinner"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/ui"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to your AgentSecrets account",
	Long: `Login to your existing AgentSecrets account.

	This will:
	1. Prompt for your email and password
	2. Authenticate with the server
	3. Decrypt your private key using your password
	4. Download and decrypt your workspace keys
	5. Cache credentials locally for future commands`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			email    string
			password string
		)

		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Email").
					Value(&email).
					Validate(func(s string) error {
						if s == "" {
							return fmt.Errorf("email is required")
						}
						return nil
					}),

				huh.NewInput().
					Title("Password").
					EchoMode(huh.EchoModePassword).
					Value(&password).
					Validate(func(s string) error {
						if s == "" {
							return fmt.Errorf("password is required")
						}
						return nil
					}),
			),
		)

		if err := form.Run(); err != nil {
			return nil
		}

		fmt.Println()

		var loginErr error
		err := spinner.New().
			Title("Logging in...").
			Action(func() {
				loginErr = authService.PerformLogin(email, password, nil, nil)
			}).
			Run()
		if err != nil {
			return err
		}

		if loginErr != nil {
			ui.Error("Login failed: " + loginErr.Error())
			return nil
		}

		fmt.Println()
		ui.Success("Logged in successfully!")
		return nil
	},
}
