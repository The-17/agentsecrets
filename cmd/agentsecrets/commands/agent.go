package commands

import (
	"fmt"
	"strings"

	"github.com/The-17/agentsecrets/pkg/capabilities"
	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/agents"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var (
	agentPolicyAllow []string
	agentPolicyDeny  []string
)

var agentCmd = &cobra.Command{
	Use:               "agent",
	Short:             "Manage agent identities and tokens",
	Long:              "Manage agent identities and tokens for the current workspace.\n\nAgents are named identities that can be bound to credential calls.\nEvery call through the proxy is logged with the calling agent's identity.\nIssued tokens provide cryptographically verified identity.",
	PersistentPreRunE: keychainAuthMiddleware,
}

var agentRegisterCmd = &cobra.Command{
	Use:   "register <name>",
	Short: "Register a new agent and issue its first token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := verifyPasswordLocally(); err != nil {
			return err
		}
		name := args[0]
		projectFlag, _ := cmd.Flags().GetString("project")
		label, _ := cmd.Flags().GetString("label")
		expires, _ := cmd.Flags().GetString("expires")
		environment, _ := cmd.Flags().GetString("env")

		if environment == "" {
			environment = config.ResolveEnvironment()
		}

		workspaceID := config.GetSelectedWorkspaceID()
		if workspaceID == "" {
			return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
		}

		projectID, err := resolveProjectID(workspaceID, projectFlag)
		if err != nil {
			return err
		}

		resp, err := app.Agents().Register(agents.RegisterRequest{
			Name:        name,
			WorkspaceID: workspaceID,
			ProjectID:   projectID,
			Environment: environment,
			Label:       label,
			ExpiresIn:   expires,
		})
		if err != nil {
			return fmt.Errorf("agent registration failed: %w", err)
		}

		cfg, _ := config.LoadGlobalConfig()
		_ = proxy.LogManagementEvent("CREATE", "agent", fmt.Sprintf("Registered agent %s", resp.Agent.Name), cfg.Email, workspaceID, projectID, environment)

		scope := "workspace"
		if projectID != "" {
			projService := app.Projects()
			projectsList, err := projService.List()
			if err == nil {
				for _, p := range projectsList {
					if p.ID == projectID {
						scope = p.Name
						break
					}
				}
			} else {
				scope = projectID
			}
		}

		fmt.Println("\n" + ui.SuccessStyle.Render("Agent registered"))
		fmt.Printf("  Name     %s\n", resp.Agent.Name)
		fmt.Printf("  Scope    %s\n", scope)
		fmt.Printf("  Token    %s\n", resp.Token)
		if resp.ExpiresAt != nil {
			fmt.Printf("  Expires  %s\n", resp.ExpiresAt.Format("2006-01-02"))
		}

		fmt.Println("\n" + ui.WarningStyle.Render("Store this token securely. It will not be shown again."))
		fmt.Printf("To use it: export AS_AGENT_TOKEN=%s\n", resp.Token)

		var storeInKeychain bool
		var confirmErr error
		if cmd.Flags().Changed("save-token") {
			storeInKeychain, _ = cmd.Flags().GetBool("save-token")
		} else {
			confirmErr = huh.NewConfirm().
				Title("Would you like to store this agent token in your local OS Keychain?").
				Description(fmt.Sprintf("This allows referencing it in your code via %s_TOKEN", strings.ToUpper(resp.Agent.Name))).
				Value(&storeInKeychain).
				Run()
		}

		if confirmErr == nil && storeInKeychain {
			if err := keyring.SetAgentToken(resp.Agent.Name, resp.Token); err != nil {
				ui.Error(fmt.Sprintf("Failed to store agent token in keychain: %v", err))
			} else {
				fmt.Println()
				ui.Success(fmt.Sprintf("Stored agent token in keychain! You can now reference it via: %s_TOKEN", strings.ToUpper(resp.Agent.Name)))
			}
		}
		fmt.Println()
		return nil
	},
}

var agentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered agents",
	RunE: func(cmd *cobra.Command, args []string) error {
		projectFlag, _ := cmd.Flags().GetString("project")

		workspaceID := config.GetSelectedWorkspaceID()
		if workspaceID == "" {
			return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
		}

		// Load projects to resolve IDs to Names in display
		projectNames := make(map[string]string)
		projService := app.Projects()
		projectsList, err := projService.List()
		if err == nil {
			for _, p := range projectsList {
				projectNames[p.ID] = p.Name
			}
		}

		var list []agents.Agent
		if projectFlag != "" {
			var projectID string
			projectID, err = resolveProjectID(workspaceID, projectFlag)
			if err != nil {
				return err
			}
			list, err = app.Agents().List(workspaceID, projectID)
			if err != nil {
				return fmt.Errorf("failed to list agents: %w", err)
			}
		} else {
			// Fetch all agents (workspace and project-scoped) in a single fast call
			list, err = app.Agents().ListAll(workspaceID)
			if err != nil {
				// Fallback to sequential listing if backend does not support include_projects
				list, err = app.Agents().List(workspaceID, "")
				if err != nil {
					return fmt.Errorf("failed to list agents: %w", err)
				}

				for _, p := range projectsList {
					if p.WorkspaceID == workspaceID {
						projAgents, err := app.Agents().List(workspaceID, p.ID)
						if err == nil {
							list = append(list, projAgents...)
						}
					}
				}
			}
		}

		if len(list) == 0 {
			fmt.Println(ui.DimStyle.Render("No agents found."))
			return nil
		}

		// Header
		fmt.Printf("%-20s %-15s %-8s %-25s %s\n", "AGENT", "SCOPE", "TOKENS", "LAST USED", "REGISTERED")
		for _, a := range list {
			scope := "workspace"
			if a.ProjectID != nil {
				if name, ok := projectNames[*a.ProjectID]; ok {
					scope = name
				} else {
					scope = *a.ProjectID
				}
			}
			lastUsed := "never"
			if a.LastUsed != nil {
				lastUsed = a.LastUsed.Format("2006-01-02 15:04 UTC")
			}
			registered := a.CreatedAt.Format("2006-01-02")
			fmt.Printf("%-20s %-15s %-8d %-25s %s\n", a.Name, scope, a.TokenCount, lastUsed, registered)
		}
		return nil
	},
}

var agentTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage agent tokens",
}

var agentTokenIssueCmd = &cobra.Command{
	Use:   "issue <name>",
	Short: "Issue a new token for an existing agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		label, _ := cmd.Flags().GetString("label")
		expires, _ := cmd.Flags().GetString("expires")
		environment, _ := cmd.Flags().GetString("env")

		if environment == "" {
			environment = config.ResolveEnvironment()
		}

		workspaceID := config.GetSelectedWorkspaceID()
		if workspaceID == "" {
			return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
		}

		agent, err := getAgentByName(workspaceID, name)
		if err != nil {
			return err
		}

		if err := verifyPasswordLocally(); err != nil {
			return err
		}

		resp, err := app.Agents().TokenIssue(workspaceID, agent.ID, agents.IssueTokenRequest{
			Environment: environment,
			Label:       label,
			ExpiresIn:   expires,
		})
		if err != nil {
			return fmt.Errorf("token issuance failed: %w", err)
		}

		cfg, _ := config.LoadGlobalConfig()
		_ = proxy.LogManagementEvent("ISSUE", "token", fmt.Sprintf("Issued token for agent %s", name), cfg.Email, workspaceID, "", environment)

		fmt.Println("\n" + ui.SuccessStyle.Render("Token issued"))
		fmt.Printf("  Agent    %s\n", name)
		fmt.Printf("  Token    %s\n", resp.Token)
		if resp.Label != "" {
			fmt.Printf("  Label    %s\n", resp.Label)
		}
		if resp.ExpiresAt != nil {
			fmt.Printf("  Expires  %s\n", resp.ExpiresAt.Format("2006-01-02"))
		}
		fmt.Println("\n" + ui.WarningStyle.Render("Store this token securely. It will not be shown again."))

		var storeInKeychain bool
		var confirmErr error
		if cmd.Flags().Changed("save-token") {
			storeInKeychain, _ = cmd.Flags().GetBool("save-token")
		} else {
			confirmErr = huh.NewConfirm().
				Title("Would you like to store this agent token in your local OS Keychain?").
				Description(fmt.Sprintf("This allows referencing it in your code via %s_TOKEN", strings.ToUpper(name))).
				Value(&storeInKeychain).
				Run()
		}

		if confirmErr == nil && storeInKeychain {
			if err := keyring.SetAgentToken(name, resp.Token); err != nil {
				ui.Error(fmt.Sprintf("Failed to store agent token in keychain: %v", err))
			} else {
				fmt.Println()
				ui.Success(fmt.Sprintf("Stored agent token in keychain! You can now reference it via: %s_TOKEN", strings.ToUpper(name)))
			}
		}
		fmt.Println()
		return nil
	},
}

var agentTokenListCmd = &cobra.Command{
	Use:   "list <name>",
	Short: "List tokens for an agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		workspaceID := config.GetSelectedWorkspaceID()
		if workspaceID == "" {
			return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
		}

		agent, err := getAgentByName(workspaceID, name)
		if err != nil {
			return err
		}

		tokens, err := app.Agents().TokenList(workspaceID, agent.ID)
		if err != nil {
			return fmt.Errorf("failed to list tokens: %w", err)
		}

		if len(tokens) == 0 {
			fmt.Println(ui.DimStyle.Render("No tokens found for agent."))
			return nil
		}

		fmt.Printf("%-20s %-15s %-15s %-25s %s\n", "TOKEN ID", "LABEL", "EXPIRES", "LAST USED", "STATUS")
		for _, t := range tokens {
			label := t.Label
			if label == "" {
				label = "(none)"
			}
			expires := "(none)"
			if t.ExpiresAt != nil {
				expires = t.ExpiresAt.Format("2006-01-02")
			}
			lastUsed := "never"
			if t.LastUsed != nil {
				lastUsed = t.LastUsed.Format("2006-01-02 15:04 UTC")
			}
			fmt.Printf("%-20s %-15s %-15s %-25s %s\n", t.ID, label, expires, lastUsed, t.Status)
		}
		return nil
	},
}

var agentTokenRevokeCmd = &cobra.Command{
	Use:   "revoke [token_id]",
	Short: "Revoke one or all tokens for an agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName, _ := cmd.Flags().GetString("agent")
		all, _ := cmd.Flags().GetBool("all")
		confirm, _ := cmd.Flags().GetBool("confirm")

		workspaceID := config.GetSelectedWorkspaceID()
		if workspaceID == "" {
			return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
		}

		if !all && len(args) == 0 {
			return fmt.Errorf("must specify <token_id> or use --all with --agent <name>")
		}

		if all {
			if agentName == "" {
				return fmt.Errorf("--agent must be provided when using --all")
			}
			if !confirm {
				fmt.Printf("Revoke all active tokens for %s? [y/N] ", agentName)
				var response string
				fmt.Scanln(&response)
				if response != "y" && response != "Y" {
					fmt.Println("Aborted.")
					return nil
				}
			}

			agent, err := getAgentByName(workspaceID, agentName)
			if err != nil {
				return err
			}

			err = app.Agents().TokenRevokeAll(workspaceID, agent.ID)
			if err != nil {
				return fmt.Errorf("failed to revoke tokens: %w", err)
			}
			fmt.Println("\nTokens revoked.")
			fmt.Println("Propagation to active proxy instances: up to 60 seconds.")
			return nil
		}

		// Revoke single token
		tokenID := args[0]
		if agentName == "" {
			return fmt.Errorf("please provide the --agent <name> for the token")
		}

		if !confirm {
			fmt.Printf("Revoke token %s for agent %s? [y/N] ", tokenID, agentName)
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				fmt.Println("Aborted.")
				return nil
			}
		}

		agent, err := getAgentByName(workspaceID, agentName)
		if err != nil {
			return err
		}

		err = app.Agents().TokenRevoke(workspaceID, agent.ID, tokenID)
		if err != nil {
			return fmt.Errorf("failed to revoke token: %w", err)
		}
		fmt.Println("\nToken revoked.")
		fmt.Println("Propagation to active proxy instances: up to 60 seconds.")
		return nil
	},
}

var agentDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete an agent registration",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		confirm, _ := cmd.Flags().GetBool("confirm")

		workspaceID := config.GetSelectedWorkspaceID()
		if workspaceID == "" {
			return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
		}

		agent, err := getAgentByName(workspaceID, name)
		if err != nil {
			return err
		}

		if !confirm {
			fmt.Printf("Delete agent %q and revoke all active tokens? [y/N] ", name)
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				fmt.Println("Aborted.")
				return nil
			}
		}

		if err := verifyPasswordLocally(); err != nil {
			return err
		}

		err = app.Agents().Delete(workspaceID, agent.ID)
		if err != nil {
			return fmt.Errorf("failed to delete agent: %w", err)
		}

		cfg, _ := config.LoadGlobalConfig()
		var projectID string
		if agent.ProjectID != nil {
			projectID = *agent.ProjectID
		}
		_ = proxy.LogManagementEvent("DELETE", "agent", fmt.Sprintf("Deleted agent %s", name), cfg.Email, workspaceID, projectID, config.ResolveEnvironment())

		fmt.Println("\nAgent deleted.")
		return nil
	},
}

func init() {
	// Root subcommands
	agentCmd.AddCommand(agentPolicyCmd)
	agentPolicyCmd.AddCommand(agentPolicyGetCmd)
	agentPolicyCmd.AddCommand(agentPolicySetCmd)

	agentPolicySetCmd.Flags().StringSliceVar(&agentPolicyAllow, "allow", nil, "comma-separated or repeatable list of allowed secret keys")
	agentPolicySetCmd.Flags().StringSliceVar(&agentPolicyDeny, "deny", nil, "comma-separated or repeatable list of denied secret keys")

	agentCmd.AddCommand(agentRegisterCmd)
	agentCmd.AddCommand(agentListCmd)
	agentCmd.AddCommand(agentTokenCmd)
	agentCmd.AddCommand(agentDeleteCmd)

	// Token subcommands
	agentTokenCmd.AddCommand(agentTokenIssueCmd)
	agentTokenCmd.AddCommand(agentTokenListCmd)
	agentTokenCmd.AddCommand(agentTokenRevokeCmd)

	// Flags for register
	agentRegisterCmd.Flags().StringP("project", "p", "", "scope to a specific project")
	agentRegisterCmd.Flags().StringP("label", "l", "", "human label for the first token")
	agentRegisterCmd.Flags().StringP("expires", "e", "", "token expiry (e.g. 30d, 90d)")
	agentRegisterCmd.Flags().String("env", "", "environment for the token (development, staging, production)")
	agentRegisterCmd.Flags().Bool("save-token", false, "save the issued token to the OS Keychain without prompting")

	// Flags for list
	agentListCmd.Flags().StringP("project", "p", "", "filter to a specific project")

	// Flags for token issue
	agentTokenIssueCmd.Flags().StringP("label", "l", "", "label for this token")
	agentTokenIssueCmd.Flags().StringP("expires", "e", "", "token expiry (e.g. 30d, 90d)")
	agentTokenIssueCmd.Flags().String("env", "", "environment for the token (development, staging, production)")
	agentTokenIssueCmd.Flags().Bool("save-token", false, "save the issued token to the OS Keychain without prompting")

	// Flags for token list

	// Flags for token revoke
	agentTokenRevokeCmd.Flags().StringP("agent", "a", "", "used with --all or specific token to identify the agent")
	agentTokenRevokeCmd.Flags().Bool("all", false, "revoke all active tokens for the agent")
	agentTokenRevokeCmd.Flags().Bool("confirm", false, "skip confirmation prompt")

	// Flags for delete
	agentDeleteCmd.Flags().Bool("confirm", false, "skip confirmation prompt")
}

var agentPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage agent capabilities/policy",
}

var agentPolicyGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get policy/capabilities for an agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		workspaceID := config.GetSelectedWorkspaceID()
		if workspaceID == "" {
			return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
		}

		agent, err := getAgentByName(workspaceID, name)
		if err != nil {
			return err
		}

		caps, err := app.Agents().GetCapabilities(workspaceID, agent.ID)
		if err != nil {
			return fmt.Errorf("failed to get agent policy: %w", err)
		}

		fmt.Printf("\nAgent Policy for %s:\n", name)
		if len(caps.AllowedSecrets) > 0 {
			fmt.Printf("  Allowed Secrets: %s\n", strings.Join(caps.AllowedSecrets, ", "))
		} else {
			fmt.Println("  Allowed Secrets: (none)")
		}
		if len(caps.DeniedSecrets) > 0 {
			fmt.Printf("  Denied Secrets:  %s\n", strings.Join(caps.DeniedSecrets, ", "))
		} else {
			fmt.Println("  Denied Secrets:  (none)")
		}
		return nil
	},
}

var agentPolicySetCmd = &cobra.Command{
	Use:   "set <name>",
	Short: "Set policy/capabilities for an agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		workspaceID := config.GetSelectedWorkspaceID()
		if workspaceID == "" {
			return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
		}

		agent, err := getAgentByName(workspaceID, name)
		if err != nil {
			return err
		}

		var projectID string
		if agent.ProjectID != nil {
			projectID = *agent.ProjectID
		}
		if projectID == "" {
			if proj, err := config.LoadProjectConfig(); err == nil && proj != nil {
				projectID = proj.ProjectID
			}
		}

		var allowed []string
		for _, s := range agentPolicyAllow {
			s = strings.TrimSpace(s)
			if s != "" {
				allowed = append(allowed, s)
			}
		}

		var denied []string
		for _, s := range agentPolicyDeny {
			s = strings.TrimSpace(s)
			if s != "" {
				denied = append(denied, s)
			}
		}

		var allKeys []string
		allKeys = append(allKeys, allowed...)
		allKeys = append(allKeys, denied...)

		if len(allKeys) > 0 {
			if projectID == "" {
				return fmt.Errorf("no project configured in current directory and agent is not associated with any project. Secret policies require a project context.")
			}
			if err := validateSecretsExist(projectID, allKeys); err != nil {
				return err
			}
		}

		if err := verifyPasswordLocally(); err != nil {
			return err
		}

		caps := capabilities.AgentCapabilities{
			AllowedSecrets: allowed,
			DeniedSecrets:  denied,
		}

		_, err = app.Agents().SetCapabilities(workspaceID, agent.ID, caps)
		if err != nil {
			return fmt.Errorf("failed to set agent policy: %w", err)
		}

		cfg, _ := config.LoadGlobalConfig()
		if agent.ProjectID != nil {
			projectID = *agent.ProjectID
		}
		_ = proxy.LogManagementEvent("UPDATE", "policy", fmt.Sprintf("Updated policy for agent %s", name), cfg.Email, workspaceID, projectID, config.ResolveEnvironment())

		fmt.Println("\n" + ui.SuccessStyle.Render("Agent policy updated successfully"))
		return nil
	},
}

func validateSecretsExist(projectID string, keys []string) error {
	if len(keys) == 0 {
		return nil
	}

	knownKeys := make(map[string]bool)

	// 1. Check local keyring
	envs := config.ValidEnvironments
	for _, env := range envs {
		if localKeys, err := keyring.ListProjectKeyNames(projectID, env); err == nil {
			for _, k := range localKeys {
				knownKeys[strings.ToUpper(k)] = true
			}
		}
	}

	// 2. Check server-side keys
	secService := app.Secrets()
	for _, env := range envs {
		if remoteKeys, err := secService.ListForEnv(env); err == nil {
			for _, k := range remoteKeys {
				knownKeys[strings.ToUpper(k.Key)] = true
			}
		}
	}

	for _, k := range keys {
		if !knownKeys[strings.ToUpper(k)] {
			return errors.New(errors.ErrSecretNotFound, fmt.Sprintf("secret %q does not exist in project", k), fmt.Errorf("Please create the secret first with: agentsecrets secrets set %s=value", k))
		}
	}

	return nil
}

func resolveProjectID(workspaceID, projectNameOrID string) (string, error) {
	if projectNameOrID == "" {
		return "", nil
	}

	projService := app.Projects()
	projList, err := projService.List()
	if err != nil {
		return "", err
	}

	for _, p := range projList {
		if p.ID == projectNameOrID || strings.EqualFold(p.Name, projectNameOrID) {
			return p.ID, nil
		}
	}

	return "", fmt.Errorf("project %q not found in workspace", projectNameOrID)
}

func getAgentByName(workspaceID, name string) (*agents.Agent, error) {
	agent, err := app.Agents().GetByName(workspaceID, name)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, errors.New(errors.ErrAgentNotFound, fmt.Sprintf("agent %q not found in this workspace", name), err)
		}
		return nil, err
	}
	return agent, nil
}
