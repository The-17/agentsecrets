package commands

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/capabilities"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var (
	policyDomains []string
	policyMethods []string
	policyAction  string
	policyRules   []string
)

var secretsPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage secret-level policies",
	Long:  `Define target constraints for individual secrets (allowed domains, allowed HTTP methods, and violation actions).`,
}

var secretsPolicySetCmd = &cobra.Command{
	Use:   "set <key>",
	Short: "Set a policy for a secret key",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsPolicySet,
}

var secretsPolicyGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get the policy for a secret key",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsPolicyGet,
}

var secretsPolicyDeleteCmd = &cobra.Command{
	Use:   "delete <key>",
	Short: "Delete/clear the policy for a secret key",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsPolicyDelete,
}

var secretsPolicyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secret policies in the current project",
	RunE:  runSecretsPolicyList,
}

func init() {
	secretsPolicySetCmd.Flags().StringSliceVar(&policyDomains, "domains", nil, "Comma-separated list of allowed domains (e.g. api.stripe.com)")
	secretsPolicySetCmd.Flags().StringSliceVar(&policyMethods, "methods", nil, "Comma-separated list of allowed HTTP methods (e.g. GET,POST)")
	secretsPolicySetCmd.Flags().StringVar(&policyAction, "action", "deny", "Violation action: deny or request_permission")
	secretsPolicySetCmd.Flags().StringSliceVar(&policyRules, "rule", nil, "Domain-specific rule in format domain:METHOD=ACTION (repeatable, e.g. api.stripe.com:GET=allow,POST=request_permission)")

	secretsPolicySetCmd.ValidArgsFunction = autocompleteSecretKeys
	secretsPolicyGetCmd.ValidArgsFunction = autocompleteSecretKeys
	secretsPolicyDeleteCmd.ValidArgsFunction = autocompleteSecretKeys

	secretsPolicyCmd.AddCommand(
		secretsPolicySetCmd,
		secretsPolicyGetCmd,
		secretsPolicyDeleteCmd,
		secretsPolicyListCmd,
	)

	secretsCmd.AddCommand(secretsPolicyCmd)
}

func runSecretsPolicySet(cmd *cobra.Command, args []string) error {
	key := args[0]

	project, err := config.LoadProjectConfig()
	if err != nil || project == nil || project.ProjectID == "" {
		return fmt.Errorf("no project configured in current directory")
	}

	env := config.ResolveEnvironment()

	// Validate that the secret key actually exists locally or remotely before prompting for password
	exists, err := secretExists(project.ProjectID, env, key)
	if err != nil {
		return err
	}

	if !exists {
		return errors.New(errors.ErrSecretNotFound, fmt.Sprintf("secret %q does not exist in project", key), fmt.Errorf("Please create the secret first with: agentsecrets secrets set %s=value", key))
	}

	// Policy changes are security-sensitive — always require password verification.
	if err := verifyPasswordLocally(); err != nil {
		return err
	}

	// Validate action
	action := capabilities.Action(strings.ToLower(policyAction))
	if action != capabilities.Deny && action != capabilities.RequestPermission {
		return fmt.Errorf("invalid action %q — must be 'deny' or 'request_permission'", policyAction)
	}

	// Build method map
	methodsMap := make(map[string]capabilities.Action)
	for _, m := range policyMethods {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		parts := strings.SplitN(m, "=", 2)
		method := strings.ToUpper(strings.TrimSpace(parts[0]))

		act := action // default action
		if len(parts) == 2 {
			customAct := capabilities.Action(strings.ToLower(strings.TrimSpace(parts[1])))
			if customAct != capabilities.Allow && customAct != capabilities.Deny && customAct != capabilities.RequestPermission {
				return fmt.Errorf("invalid action %q for method %s — must be 'allow', 'deny', or 'request_permission'", parts[1], method)
			}
			act = customAct
		}
		methodsMap[method] = act
	}

	var domains []string
	for _, d := range policyDomains {
		domains = append(domains, strings.ToLower(strings.TrimSpace(d)))
	}

	// Validate that all policy domains are in the workspace allowlist.
	if len(domains) > 0 && project.WorkspaceID != "" {
		allowlist, alErr := keyring.GetWorkspaceAllowlist(project.WorkspaceID)
		if alErr == nil && len(allowlist) > 0 {
			allowlistSet := make(map[string]bool, len(allowlist))
			for _, d := range allowlist {
				allowlistSet[strings.ToLower(d)] = true
			}
			for _, d := range domains {
				if !allowlistSet[d] {
					return fmt.Errorf("domain '%s' is not in your workspace allowlist. Add it first with: agentsecrets workspace allowlist add %s", d, d)
				}
			}
		}
	}

	var rules []capabilities.PolicyRule
	if len(policyRules) > 0 {
		rulesMap := make(map[string]map[string]capabilities.Action)
		for _, rStr := range policyRules {
			rStr = strings.TrimSpace(rStr)
			if rStr == "" {
				continue
			}
			parts := strings.SplitN(rStr, ":", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				return fmt.Errorf("invalid rule format %q — must be domain:METHOD=ACTION", rStr)
			}
			domain := strings.ToLower(strings.TrimSpace(parts[0]))
			methodsPart := strings.TrimSpace(parts[1])

			methodsMapForDom, exists := rulesMap[domain]
			if !exists {
				methodsMapForDom = make(map[string]capabilities.Action)
				rulesMap[domain] = methodsMapForDom
			}

			pairs := strings.Split(methodsPart, ",")
			for _, pair := range pairs {
				pair = strings.TrimSpace(pair)
				if pair == "" {
					continue
				}
				eqParts := strings.SplitN(pair, "=", 2)
				if len(eqParts) != 2 || eqParts[0] == "" || eqParts[1] == "" {
					return fmt.Errorf("invalid method-action pair %q in rule %q — must be METHOD=ACTION", pair, rStr)
				}
				m := strings.ToUpper(strings.TrimSpace(eqParts[0]))
				actStr := strings.ToLower(strings.TrimSpace(eqParts[1]))
				act := capabilities.Action(actStr)
				if act != capabilities.Allow && act != capabilities.Deny && act != capabilities.RequestPermission {
					return fmt.Errorf("invalid action %q for method %s — must be 'allow', 'deny', or 'request_permission'", actStr, m)
				}
				methodsMapForDom[m] = act
			}
		}

		var sortedDomains []string
		for dom := range rulesMap {
			sortedDomains = append(sortedDomains, dom)
		}
		sort.Strings(sortedDomains)

		for _, dom := range sortedDomains {
			if project.WorkspaceID != "" {
				allowlist, alErr := keyring.GetWorkspaceAllowlist(project.WorkspaceID)
				if alErr == nil && len(allowlist) > 0 {
					allowlistSet := make(map[string]bool, len(allowlist))
					for _, d := range allowlist {
						allowlistSet[strings.ToLower(d)] = true
					}
					if !allowlistSet[dom] {
						return fmt.Errorf("domain '%s' is not in your workspace allowlist. Add it first with: agentsecrets workspace allowlist add %s", dom, dom)
					}
				}
			}

			rules = append(rules, capabilities.PolicyRule{
				Domain:  dom,
				Methods: rulesMap[dom],
			})
		}
	}

	policy := capabilities.SecretPolicy{
		Domains: domains,
		Methods: methodsMap,
		Rules:   rules,
	}

	policyBytes, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to serialize policy: %w", err)
	}

	// 1. Save secret policy to cloud
	resp, err := app.API().Call("secrets.set_policy", "PUT", policy, map[string]string{
		"project_id":  project.ProjectID,
		"environment": env,
		"key":         key,
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to save policy to cloud: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return app.API().DecodeError(resp)
	}

	// 2. Save secret policy to local keyring
	if err := keyring.SetSecretPolicy(project.ProjectID, env, key, policyBytes); err != nil {
		return fmt.Errorf("failed to save secret policy to keyring: %w", err)
	}

	// Log management event
	cfg, _ := config.LoadGlobalConfig()
	_ = proxy.LogManagementEvent("UPDATE", "policy", fmt.Sprintf("Updated policy for secret %s", key), cfg.Email, project.WorkspaceID, project.ProjectID, env)

	ui.Success(fmt.Sprintf("Policy updated for secret %s", key))
	return nil
}

func runSecretsPolicyGet(cmd *cobra.Command, args []string) error {
	key := args[0]

	project, err := config.LoadProjectConfig()
	if err != nil || project == nil || project.ProjectID == "" {
		return fmt.Errorf("no project configured in current directory")
	}

	env := config.ResolveEnvironment()
	policyBytes, err := keyring.GetSecretPolicy(project.ProjectID, env, key)
	if err != nil {
		return fmt.Errorf("failed to retrieve policy: %w", err)
	}

	if len(policyBytes) == 0 {
		fmt.Printf("No policy configured for secret %s (unrestricted)\n", key)
		return nil
	}

	var policy capabilities.SecretPolicy
	if err := json.Unmarshal(policyBytes, &policy); err != nil {
		return fmt.Errorf("failed to parse policy: %w", err)
	}

	fmt.Printf("\nSecret Policy for %s:\n", key)
	if len(policy.Rules) > 0 {
		fmt.Println("  Rules (Domain-Specific):")
		for _, rule := range policy.Rules {
			var methods []string
			if len(rule.Methods) > 0 {
				for m, act := range rule.Methods {
					methods = append(methods, fmt.Sprintf("%s (%s)", m, act))
				}
				sort.Strings(methods)
				fmt.Printf("    - %s: %s\n", rule.Domain, strings.Join(methods, ", "))
			} else {
				fmt.Printf("    - %s: (any method allowed)\n", rule.Domain)
			}
		}

		if len(policy.Domains) > 0 || len(policy.Methods) > 0 {
			fmt.Println("\n  Global Fallbacks (Overridden by Rules above):")
			if len(policy.Domains) > 0 {
				fmt.Printf("    Allowed Domains: %s (all other domains denied)\n", strings.Join(policy.Domains, ", "))
			}
			if len(policy.Methods) > 0 {
				var methods []string
				for m, act := range policy.Methods {
					methods = append(methods, fmt.Sprintf("%s (%s)", m, act))
				}
				sort.Strings(methods)
				fmt.Printf("    Allowed Methods: %s\n", strings.Join(methods, ", "))
			}
		}
	} else {
		if len(policy.Domains) > 0 {
			fmt.Printf("  Allowed Domains: %s (all other domains denied)\n", strings.Join(policy.Domains, ", "))
		} else {
			fmt.Println("  Allowed Domains: (any)")
		}

		if len(policy.Methods) > 0 {
			var methods []string
			for m, act := range policy.Methods {
				methods = append(methods, fmt.Sprintf("%s (%s)", m, act))
			}
			sort.Strings(methods)
			fmt.Printf("  Allowed Methods: %s\n", strings.Join(methods, ", "))
		} else {
			fmt.Println("  Allowed Methods: (any)")
		}
	}
	fmt.Println()

	return nil
}

func runSecretsPolicyDelete(cmd *cobra.Command, args []string) error {
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

	// Policy changes are security-sensitive — always require password verification.
	if err := verifyPasswordLocally(); err != nil {
		return err
	}

	// 1. Delete on cloud API (by setting to empty policy)
	emptyPolicy := capabilities.SecretPolicy{}
	resp, err := app.API().Call("secrets.set_policy", "PUT", emptyPolicy, map[string]string{
		"project_id":  project.ProjectID,
		"environment": env,
		"key":         key,
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to delete policy on cloud: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return app.API().DecodeError(resp)
	}

	// 2. Deleting the policy locally is setting it to nil
	if err := keyring.SetSecretPolicy(project.ProjectID, env, key, nil); err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	// Log management event
	cfg, _ := config.LoadGlobalConfig()
	_ = proxy.LogManagementEvent("DELETE", "policy", fmt.Sprintf("Deleted policy for secret %s", key), cfg.Email, project.WorkspaceID, project.ProjectID, env)

	ui.Success(fmt.Sprintf("Policy deleted for secret %s", key))
	return nil
}

func runSecretsPolicyList(cmd *cobra.Command, _ []string) error {
	project, err := config.LoadProjectConfig()
	if err != nil || project == nil || project.ProjectID == "" {
		return fmt.Errorf("no project configured in current directory")
	}

	env := config.ResolveEnvironment()

	keys, err := keyring.ListProjectKeyNames(project.ProjectID, env)
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	if len(keys) == 0 {
		ui.Info("No secrets found in this project.")
		return nil
	}

	type keyPolicy struct {
		Key     string
		Domains string
		Methods string
	}

	var list []keyPolicy
	for _, key := range keys {
		policyBytes, err := keyring.GetSecretPolicy(project.ProjectID, env, key)
		if err == nil && len(policyBytes) > 0 {
			var policy capabilities.SecretPolicy
			if err := json.Unmarshal(policyBytes, &policy); err == nil {
				domains := "(any)"
				methods := "(any)"
				if len(policy.Rules) > 0 {
					var ruleDomains []string
					var ruleMethods []string
					for _, r := range policy.Rules {
						ruleDomains = append(ruleDomains, r.Domain)
						for m, act := range r.Methods {
							ruleMethods = append(ruleMethods, fmt.Sprintf("%s:%s (%s)", r.Domain, m, act))
						}
					}
					domains = strings.Join(ruleDomains, ", ")
					if len(ruleMethods) > 0 {
						sort.Strings(ruleMethods)
						methods = strings.Join(ruleMethods, ", ")
					}
				} else {
					if len(policy.Domains) > 0 {
						domains = strings.Join(policy.Domains, ", ")
					}
					if len(policy.Methods) > 0 {
						var mList []string
						for m, act := range policy.Methods {
							mList = append(mList, fmt.Sprintf("%s (%s)", m, act))
						}
						sort.Strings(mList)
						methods = strings.Join(mList, ", ")
					}
				}
				list = append(list, keyPolicy{
					Key:     key,
					Domains: domains,
					Methods: methods,
				})
			}
		}
	}

	if len(list) == 0 {
		ui.Info("No secret-level policies configured in this project.")
		return nil
	}

	headers := []string{"Secret Key", "Allowed Domains", "Allowed Methods"}
	rows := make([][]string, len(list))
	for i, item := range list {
		rows[i] = []string{ui.BrandStyle.Render(item.Key), item.Domains, item.Methods}
	}

	fmt.Printf("\nSecret Policies for Environment: %s\n\n", ui.BrandStyle.Render(env))
	fmt.Println(ui.RenderTable(headers, rows))
	fmt.Println()

	return nil
}
