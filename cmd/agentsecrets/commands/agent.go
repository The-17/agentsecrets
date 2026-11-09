package commands

import (
	"fmt"
	"strings"

	"github.com/The-17/agentsecrets/pkg/capabilities"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/agents"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/gateway"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var (
	agentPolicyAllow []string
	agentPolicyDeny  []string

	// agentCreateStoreSecret defaults to storing the minted token as the
	// project secret AGENTSECRETS_TOKEN so workloads pick it up automatically.
	agentCreateStoreSecret bool
)

var agentCmd = &cobra.Command{
	Use:               "agent",
	Short:             "Manage agent identities and tokens",
	Long:              "Manage agent identities and tokens for the current workspace.\n\nAgents are named identities that can be bound to credential calls.\nEvery call through the proxy is logged with the calling agent's identity.\nIssued tokens provide cryptographically verified identity.",
	PersistentPreRunE: keychainAuthMiddleware,
}

var agentRegisterCmd = &cobra.Command{
	Use:        "register <name>",
	Short:      "Register a new agent and issue its first token (alias of 'create')",
	Deprecated: "use 'agent create' instead, which stores the token as a project secret for you",
	Args:       cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectFlag, _ := cmd.Flags().GetString("project")
		label, _ := cmd.Flags().GetString("label")
		expires, _ := cmd.Flags().GetString("expires")
		environment, _ := cmd.Flags().GetString("env")

		caps := &capabilities.AgentCapabilities{}
		hasCaps := false
		if cmd.Flags().Changed("env-read") {
			v, _ := cmd.Flags().GetBool("env-read")
			caps.CanEnvRead = &v
			hasCaps = true
		}
		if cmd.Flags().Changed("proxy-resolve") {
			v, _ := cmd.Flags().GetBool("proxy-resolve")
			caps.CanProxyResolve = &v
			hasCaps = true
		}
		var capsReq *capabilities.AgentCapabilities
		if hasCaps {
			capsReq = caps
		}

		in := agentCreateInput{
			Name:        args[0],
			ProjectFlag: projectFlag,
			Label:       label,
			Expires:     expires,
			Environment: environment,
			Caps:        capsReq,
		}
		if cmd.Flags().Changed("save-token") {
			v, _ := cmd.Flags().GetBool("save-token")
			in.SaveToken = &v
		}
		return runAgentCreate(cmd, in)
	},
}

// agentCreateCmd is the v4 one-command identity: bind an agent, mint its first
// token, grant capability scopes, and (by default) store that token as the
// project secret AGENTSECRETS_TOKEN so downstream workloads pick it up with no
// manual export.
var agentCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a v4 agent identity and its first token (one command)",
	Long: "Create a named agent bound to a workspace or project, mint its first token, " +
		"and (by default) store that token as the project secret AGENTSECRETS_TOKEN so downstream " +
		"workloads pick it up with no further setup.\n\n" +
		"Scopes are granted with --allow. The control plane can mint only secrets:env and " +
		"secrets:proxy today; any other scope fails closed rather than being silently dropped.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		scope, _ := cmd.Flags().GetString("scope")
		scope = strings.ToLower(strings.TrimSpace(scope))
		switch scope {
		case "project", "workspace":
		default:
			return fmt.Errorf("invalid --scope %q; use 'project' or 'workspace'", scope)
		}

		projectFlag, _ := cmd.Flags().GetString("project")
		if scope == "workspace" {
			if projectFlag != "" {
				return fmt.Errorf("--scope workspace cannot be combined with --project; a workspace-wide token has no project binding")
			}
		} else if projectFlag == "" {
			return fmt.Errorf("--scope project requires --project <name>")
		}

		allow, _ := cmd.Flags().GetStringSlice("allow")
		caps, err := capabilities.ParseScopes(allow)
		if err != nil {
			return err
		}

		in := agentCreateInput{
			Name:        args[0],
			Scope:       scope,
			ProjectFlag: projectFlag,
			Label:       cmd.Flag("label").Value.String(),
			Expires:     cmd.Flag("expires").Value.String(),
			Environment: cmd.Flag("env").Value.String(),
			Caps:        caps,
			StoreSecret: agentCreateStoreSecret,
		}
		if cmd.Flags().Changed("save-token") {
			v, _ := cmd.Flags().GetBool("save-token")
			in.SaveToken = &v
		}
		return runAgentCreate(cmd, in)
	},
}

// agentCreateInput is the resolved request shared by `register` and `create`.
type agentCreateInput struct {
	Name        string
	Scope       string // "project" | "workspace" (informational; resolution uses ProjectFlag)
	ProjectFlag string
	Label       string
	Expires     string
	Environment string
	Caps        *capabilities.AgentCapabilities
	SaveToken   *bool // nil => prompt the user
	StoreSecret bool  // store token as project secret AGENTSECRETS_TOKEN
}

// runAgentCreate is the single implementation behind both `register` and
// `create`, so the two commands cannot drift.
func runAgentCreate(cmd *cobra.Command, in agentCreateInput) error {
	if err := verifyPasswordLocally(); err != nil {
		return err
	}

	environment := in.Environment
	if environment == "" {
		environment = config.ResolveEnvironment()
	}
	environment, err := config.ParseEnvironment(environment)
	if err != nil {
		return err
	}

	workspaceID, err := requireWorkspace()
	if err != nil {
		return err
	}

	projectID, err := resolveProjectID(workspaceID, in.ProjectFlag)
	if err != nil {
		return err
	}

	expiresDays, err := agents.ParseExpiresInDays(in.Expires)
	if err != nil {
		return fmt.Errorf("invalid --expires: %w", err)
	}

	// Proof-of-possession (cnf/jkt) activation is intentionally deferred. Private
	// key transport to the workload that later uses this token is an open ADR
	// decision; minting an ephemeral, process-local key here would silently guess
	// it and brick the token once the control plane starts honoring cnf_key. The
	// cnf_key wire field on RegisterRequest stays as an inert hook for that step.
	resp, err := app.Agents().Register(agents.RegisterRequest{
		Name:          in.Name,
		WorkspaceID:   workspaceID,
		ProjectID:     projectID,
		Environment:   environment,
		Label:         in.Label,
		ExpiresInDays: expiresDays,
		Capabilities:  in.Caps,
	})
	if err != nil {
		return fmt.Errorf("agent creation failed: %w", err)
	}

	cfg, _ := config.LoadGlobalConfig()
	_ = proxy.LogManagementEvent("CREATE", "agent", fmt.Sprintf("Created agent %s", resp.Agent.Name), cfg.Email, workspaceID, projectID, environment)

	scopeName := "workspace"
	if projectID != "" {
		scopeName = in.ProjectFlag
		if scopeName == "" {
			if projectsList, e := app.Projects().List(); e == nil {
				for _, p := range projectsList {
					if p.ID == projectID {
						scopeName = p.Name
						break
					}
				}
			}
			if scopeName == "" {
				scopeName = projectID
			}
		}
	}

	fmt.Println("\n" + ui.SuccessStyle.Render("Agent created"))
	fmt.Printf("  Name   %s\n", resp.Agent.Name)
	fmt.Printf("  Scope  %s\n", scopeName)
	fmt.Printf("  Env    %s\n", environment)
	if resp.ExpiresAt != nil {
		fmt.Printf("  Expires %s\n", resp.ExpiresAt.Format("2006-01-02"))
	}
	if in.Caps != nil {
		granted := []string{}
		if in.Caps.CanEnvRead != nil && *in.Caps.CanEnvRead {
			granted = append(granted, capabilities.ScopeEnvRead)
		}
		if in.Caps.CanProxyResolve != nil && *in.Caps.CanProxyResolve {
			granted = append(granted, capabilities.ScopeProxyResolve)
		}
		fmt.Printf("  Scopes %s\n", strings.Join(granted, ", "))
	}

	// Chicken-and-egg closer: store the token as the project secret so the next
	// workload picks it up with no manual export. Fail soft — the token is
	// already minted and unrecoverable, so a store failure must warn, never
	// abort (the user can always copy the export line below).
	if in.StoreSecret {
		if err := storeProjectToken(projectID, resp.Token); err != nil {
			ui.Warning(fmt.Sprintf("Token not stored as project secret: %s", err))
		} else {
			fmt.Println()
			ui.Success(fmt.Sprintf("Stored token as project secret %s — workloads will pick it up automatically", gateway.WorkloadTokenEnv))
		}
	}

	fmt.Println("\n" + ui.WarningStyle.Render("Store this token securely. It will not be shown again."))
	fmt.Printf("To use it: export %s=%s\n", gateway.WorkloadTokenEnv, resp.Token)

	var storeInKeychain bool
	if in.SaveToken != nil {
		storeInKeychain = *in.SaveToken
	} else {
		storeInKeychain = confirmHuh(
			"Would you like to store this agent token in your local OS Keychain?",
			fmt.Sprintf("This allows referencing it in your code via %s_TOKEN", strings.ToUpper(resp.Agent.Name)),
		)
	}
	if storeInKeychain {
		if err := keyring.SetAgentToken(resp.Agent.Name, resp.Token); err != nil {
			ui.Error(fmt.Sprintf("Failed to store agent token in keychain: %v", err))
		} else {
			fmt.Println()
			ui.Success(fmt.Sprintf("Stored agent token in keychain! You can now reference it via: %s_TOKEN", strings.ToUpper(resp.Agent.Name)))
		}
	}
	fmt.Println()
	return nil
}

// storeProjectToken writes the minted token as the project secret
// AGENTSECRETS_TOKEN in the current project. It refuses to write to a project
// other than the one the agent was bound to, and returns an actionable error
// (not a failure) when there is no project context in the current directory.
func storeProjectToken(projectID, token string) error {
	pc, err := config.LoadProjectConfig()
	if err != nil || pc == nil || pc.ProjectID == "" {
		return fmt.Errorf("no project in the current directory; set it yourself: export %s=%s", gateway.WorkloadTokenEnv, token)
	}
	if projectID != "" && pc.ProjectID != projectID {
		return fmt.Errorf("current directory is project %s, not the target %s; not writing the token there", pc.ProjectID, projectID)
	}
	if err := app.Secrets().Set(gateway.WorkloadTokenEnv, token); err != nil {
		return fmt.Errorf("could not write project secret: %w", err)
	}
	return nil
}

var agentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered agents",
	RunE: func(cmd *cobra.Command, args []string) error {
		projectFlag, _ := cmd.Flags().GetString("project")

		workspaceID, err := requireWorkspace()
		if err != nil {
			return err
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
		environment, err := config.ParseEnvironment(environment)
		if err != nil {
			return err
		}

		workspaceID, err := requireWorkspace()
		if err != nil {
			return err
		}

		agent, err := getAgentByName(workspaceID, name)
		if err != nil {
			return err
		}

		if err := verifyPasswordLocally(); err != nil {
			return err
		}

		expiresDays, err := agents.ParseExpiresInDays(expires)
		if err != nil {
			return fmt.Errorf("invalid --expires: %w", err)
		}

		resp, err := app.Agents().TokenIssue(workspaceID, agent.ID, agents.IssueTokenRequest{
			Environment:   environment,
			Label:         label,
			ExpiresInDays: expiresDays,
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
		if cmd.Flags().Changed("save-token") {
			storeInKeychain, _ = cmd.Flags().GetBool("save-token")
		} else {
			storeInKeychain = confirmHuh(
				"Would you like to store this agent token in your local OS Keychain?",
				fmt.Sprintf("This allows referencing it in your code via %s_TOKEN", strings.ToUpper(name)),
			)
		}

		if storeInKeychain {
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

		workspaceID, err := requireWorkspace()
		if err != nil {
			return err
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

		fmt.Printf("%-20s %-15s %-15s %-25s %-20s %s\n", "TOKEN ID", "LABEL", "EXPIRES", "LAST USED", "STATUS", "ROTATION")
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
			rotation := t.RotationState
			if rotation == "" {
				rotation = "active"
			}
			if t.RotationPeriodDays != nil && *t.RotationPeriodDays > 0 {
				rotation = fmt.Sprintf("%s/%dd", rotation, *t.RotationPeriodDays)
			}
			fmt.Printf("%-20s %-15s %-15s %-25s %-20s %s\n", t.ID, label, expires, lastUsed, t.Status, rotation)
		}
		return nil
	},
}

var agentTokenRotateCmd = &cobra.Command{
	Use:   "rotate <token_id>",
	Short: "Rotate a token: mint a successor with overlap (routine) or immediate revoke (compromise)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tokenID := args[0]
		agentName, _ := cmd.Flags().GetString("agent")
		overlapHours, _ := cmd.Flags().GetInt("overlap-hours")
		compromise, _ := cmd.Flags().GetBool("compromise")
		confirm, _ := cmd.Flags().GetBool("confirm")

		workspaceID, err := requireWorkspace()
		if err != nil {
			return err
		}
		if agentName == "" {
			return fmt.Errorf("please provide the --agent <name> for the token")
		}

		agent, err := getAgentByName(workspaceID, agentName)
		if err != nil {
			return err
		}

		reason := "routine"
		if compromise {
			reason = "compromise"
		}
		prompt := fmt.Sprintf("Rotate token %s for agent %s? The old token stays valid for %dh. [y/N] ", tokenID, agentName, overlapHours)
		if compromise {
			prompt = fmt.Sprintf("Compromise-rotate token %s for agent %s? The old token dies immediately and the family is poisoned. [y/N] ", tokenID, agentName)
		}
		if !confirmProceed(confirm, prompt) {
			fmt.Println("Aborted.")
			return nil
		}

		if err := verifyPasswordLocally(); err != nil {
			return err
		}

		resp, err := app.Agents().TokenRotate(workspaceID, agent.ID, tokenID, agents.RotateTokenRequest{
			OverlapHours: &overlapHours,
			Reason:       reason,
		})
		if err != nil {
			return fmt.Errorf("token rotation failed: %w", err)
		}

		cfg, _ := config.LoadGlobalConfig()
		_ = proxy.LogManagementEvent("ROTATE", "token", fmt.Sprintf("Rotated token for agent %s", agentName), cfg.Email, workspaceID, "", config.ResolveEnvironment())

		fmt.Println("\n" + ui.SuccessStyle.Render("Token rotated"))
		fmt.Printf("  Agent    %s\n", agentName)
		fmt.Printf("  Token    %s\n", resp.Token)
		fmt.Printf("  Family   %s\n", resp.Rotation.FamilyID)
		if resp.Rotation.OverlapUntil != "" {
			fmt.Printf("  Old valid until %s\n", resp.Rotation.OverlapUntil)
		} else {
			fmt.Println("  Old token revoked immediately (compromise)")
		}
		fmt.Println("\n" + ui.WarningStyle.Render("Store this token securely. It will not be shown again."))
		fmt.Println()
		return nil
	},
}

var agentTokenRotationCmd = &cobra.Command{
	Use:   "rotation",
	Short: "Manage token rotation cadence",
}

var agentTokenRotationSetCmd = &cobra.Command{
	Use:   "set <token_id>",
	Short: "Arm (or disarm) an automated rotation cadence for a token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tokenID := args[0]
		agentName, _ := cmd.Flags().GetString("agent")
		periodDays, _ := cmd.Flags().GetInt("period-days")
		overlapHours, _ := cmd.Flags().GetInt("overlap-hours")
		disable, _ := cmd.Flags().GetBool("disable")

		workspaceID, err := requireWorkspace()
		if err != nil {
			return err
		}
		if agentName == "" {
			return fmt.Errorf("please provide the --agent <name> for the token")
		}
		if disable == (periodDays <= 0) {
			return fmt.Errorf("provide --period-days (>0) to arm, or --disable to disarm")
		}

		agent, err := getAgentByName(workspaceID, agentName)
		if err != nil {
			return err
		}

		req := agents.RotationPolicyRequest{Enabled: !disable}
		if !disable {
			req.PeriodDays = &periodDays
			if cmd.Flags().Changed("overlap-hours") {
				req.OverlapHours = &overlapHours
			}
		}
		resp, err := app.Agents().TokenRotationSet(workspaceID, agent.ID, tokenID, req)
		if err != nil {
			return fmt.Errorf("rotation policy update failed: %w", err)
		}

		if disable {
			fmt.Println("\nRotation cadence disarmed for token " + tokenID + ".")
			return nil
		}
		fmt.Println("\n" + ui.SuccessStyle.Render("Rotation cadence armed"))
		fmt.Printf("  Token    %s\n", tokenID)
		fmt.Printf("  Every    %d days\n", periodDays)
		fmt.Printf("  Next     %s\n", resp.Rotation.NextRotation)
		fmt.Println("  Execution is Pro-gated in the Cloud Resolver; manual rotate stays free.")
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

		workspaceID, err := requireWorkspace()
		if err != nil {
			return err
		}

		if !all && len(args) == 0 {
			return fmt.Errorf("must specify <token_id> or use --all with --agent <name>")
		}

		if all {
			if agentName == "" {
				return fmt.Errorf("--agent must be provided when using --all")
			}
			if !confirmProceed(confirm, fmt.Sprintf("Revoke all active tokens for %s? [y/N] ", agentName)) {
				fmt.Println("Aborted.")
				return nil
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

		if !confirmProceed(confirm, fmt.Sprintf("Revoke token %s for agent %s? [y/N] ", tokenID, agentName)) {
			fmt.Println("Aborted.")
			return nil
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

		workspaceID, err := requireWorkspace()
		if err != nil {
			return err
		}

		agent, err := getAgentByName(workspaceID, name)
		if err != nil {
			return err
		}

		if !confirmProceed(confirm, fmt.Sprintf("Delete agent %q and revoke all active tokens? [y/N] ", name)) {
			fmt.Println("Aborted.")
			return nil
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
	agentPolicySetCmd.Flags().Bool("env-read", false, "grant headless environment delivery scope (can_env_read); use --env-read=false to revoke")
	agentPolicySetCmd.Flags().Bool("proxy-resolve", false, "grant proxy credential resolution scope (can_proxy_resolve); use --proxy-resolve=false to revoke")

	agentCmd.AddCommand(agentRegisterCmd)
	agentCmd.AddCommand(agentCreateCmd)
	agentCmd.AddCommand(agentListCmd)
	agentCmd.AddCommand(agentTokenCmd)
	agentCmd.AddCommand(agentDeleteCmd)

	// Token subcommands
	agentTokenCmd.AddCommand(agentTokenIssueCmd)
	agentTokenCmd.AddCommand(agentTokenListCmd)
	agentTokenCmd.AddCommand(agentTokenRevokeCmd)
	agentTokenCmd.AddCommand(agentTokenRotateCmd)
	agentTokenCmd.AddCommand(agentTokenRotationCmd)
	agentTokenRotationCmd.AddCommand(agentTokenRotationSetCmd)

	// Flags for register
	agentRegisterCmd.Flags().StringP("project", "p", "", "scope to a specific project")
	agentRegisterCmd.Flags().StringP("label", "l", "", "human label for the first token")
	agentRegisterCmd.Flags().StringP("expires", "e", "", "token expiry (e.g. 30d, 90d)")
	agentRegisterCmd.Flags().String("env", "", "environment for the token (development, staging, production, or a custom name)")
	agentRegisterCmd.Flags().Bool("save-token", false, "save the issued token to the OS Keychain without prompting")
	agentRegisterCmd.Flags().Bool("env-read", false, "grant headless environment delivery scope (can_env_read) at creation")
	agentRegisterCmd.Flags().Bool("proxy-resolve", false, "grant proxy credential resolution scope (can_proxy_resolve) at creation")

	// Flags for create (the v4 command)
	agentCreateCmd.Flags().String("scope", "project", "binding scope: 'project' (default) or 'workspace'")
	agentCreateCmd.Flags().StringP("project", "p", "", "project to bind the agent to (required when --scope project)")
	agentCreateCmd.Flags().StringP("label", "l", "", "human label for the first token")
	agentCreateCmd.Flags().StringP("expires", "e", "", "token expiry (e.g. 30d, 90d)")
	agentCreateCmd.Flags().String("env", "", "environment for the token (development, staging, production, or a custom name)")
	agentCreateCmd.Flags().StringSlice("allow", nil, "capability scopes to grant: secrets:env, secrets:proxy (comma- or space-separated, repeatable)")
	agentCreateCmd.Flags().Bool("save-token", false, "save the issued token to the OS Keychain without prompting")
	agentCreateCmd.Flags().BoolVar(&agentCreateStoreSecret, "store-secret", true, "store the token as project secret AGENTSECRETS_TOKEN so workloads pick it up automatically")

	// Flags for list
	agentListCmd.Flags().StringP("project", "p", "", "filter to a specific project")

	// Flags for token issue
	agentTokenIssueCmd.Flags().StringP("label", "l", "", "label for this token")
	agentTokenIssueCmd.Flags().StringP("expires", "e", "", "token expiry (e.g. 30d, 90d)")
	agentTokenIssueCmd.Flags().String("env", "", "environment for the token (development, staging, production, or a custom name)")
	agentTokenIssueCmd.Flags().Bool("save-token", false, "save the issued token to the OS Keychain without prompting")

	// Flags for token list

	// Flags for token revoke
	agentTokenRevokeCmd.Flags().StringP("agent", "a", "", "used with --all or specific token to identify the agent")
	agentTokenRevokeCmd.Flags().Bool("all", false, "revoke all active tokens for the agent")

	// Flags for token rotate
	agentTokenRotateCmd.Flags().StringP("agent", "a", "", "identify the agent owning the token")
	agentTokenRotateCmd.Flags().Int("overlap-hours", 24, "routine-rotation grace window in hours")
	agentTokenRotateCmd.Flags().Bool("compromise", false, "zero overlap: revoke the old token immediately and poison the family")
	agentTokenRotateCmd.Flags().Bool("confirm", false, "skip the confirmation prompt")

	// Flags for token rotation set
	agentTokenRotationSetCmd.Flags().StringP("agent", "a", "", "identify the agent owning the token")
	agentTokenRotationSetCmd.Flags().Int("period-days", 0, "rotation cadence in days (1-365)")
	agentTokenRotationSetCmd.Flags().Int("overlap-hours", 0, "routine-rotation grace window in hours")
	agentTokenRotationSetCmd.Flags().Bool("disable", false, "disarm the rotation cadence")
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
		workspaceID, err := requireWorkspace()
		if err != nil {
			return err
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
		scope := func(v *bool) string {
			switch {
			case v == nil:
				return "unset"
			case *v:
				return "granted"
			default:
				return "revoked"
			}
		}
		fmt.Printf("  can_env_read:      %s\n", scope(caps.CanEnvRead))
		fmt.Printf("  can_proxy_resolve: %s\n", scope(caps.CanProxyResolve))
		return nil
	},
}

var agentPolicySetCmd = &cobra.Command{
	Use:   "set <name>",
	Short: "Set policy/capabilities for an agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		workspaceID, err := requireWorkspace()
		if err != nil {
			return err
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
		// Capability scopes: only send when the user explicitly set the flag so
		// the server preserves whatever was there (and never wipes it).
		if cmd.Flags().Changed("env-read") {
			v, _ := cmd.Flags().GetBool("env-read")
			caps.CanEnvRead = &v
		}
		if cmd.Flags().Changed("proxy-resolve") {
			v, _ := cmd.Flags().GetBool("proxy-resolve")
			caps.CanProxyResolve = &v
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
	root, _ := config.GetProjectRoot()
	envs, err := app.Secrets().Environments(projectID, root)
	if err != nil {
		return fmt.Errorf("list environments: %w", err)
	}
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
