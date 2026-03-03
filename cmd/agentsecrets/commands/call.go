package commands

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var (
	callURL      string
	callMethod   string
	callBody     string
	callBearer   string
	callBasic    string
	callHeaders  []string // "X-API-Key=SECRET_NAME"
	callQueries  []string // "api_key=SECRET_NAME"
	callBodyFields []string // "json.path=SECRET_NAME"
	callFormFields []string // "field=SECRET_NAME"
)

var callCmd = &cobra.Command{
	Use:   "call",
	Short: "Make an authenticated API call (credentials never exposed)",
	Long: `Make a one-shot authenticated API call. Credentials are resolved
	from the OS keychain and injected into the request — they are never
	printed or exposed to your AI assistant.

	Examples:
	# Bearer token (most common)
	agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY

	# POST with body
	agentsecrets call --url https://api.stripe.com/v1/charges \
		--method POST --bearer STRIPE_KEY \
		--body '{"amount":1000,"currency":"usd","source":"tok_visa"}'

	# Custom header
	agentsecrets call --url https://api.example.com/data \
		--header X-API-Key=MY_KEY

	# Query parameter
	agentsecrets call --url https://maps.googleapis.com/maps/api/geocode/json \
		--query key=GOOGLE_MAPS_KEY

	# Multiple injections
	agentsecrets call --url https://api.example.com/data \
		--bearer AUTH_TOKEN --header X-Org-ID=ORG_SECRET`,
	SilenceUsage: true,
	RunE: runCall,
}

func init() {
	callCmd.Flags().StringVar(&callURL, "url", "", "Target API URL (required)")
	callCmd.Flags().StringVar(&callMethod, "method", "GET", "HTTP method")
	callCmd.Flags().StringVar(&callBody, "body", "", "Request body (JSON string)")
	callCmd.Flags().StringVar(&callBearer, "bearer", "", "Bearer token secret key name")
	callCmd.Flags().StringVar(&callBasic, "basic", "", "Basic auth secret key name")
	callCmd.Flags().StringArrayVar(&callHeaders, "header", nil, "Header injection: HeaderName=SECRET_KEY (repeatable)")
	callCmd.Flags().StringArrayVar(&callQueries, "query", nil, "Query injection: param=SECRET_KEY (repeatable)")
	callCmd.Flags().StringArrayVar(&callBodyFields, "body-field", nil, "Body injection: json.path=SECRET_KEY (repeatable)")
	callCmd.Flags().StringArrayVar(&callFormFields, "form-field", nil, "Form injection: field=SECRET_KEY (repeatable)")
	_ = callCmd.MarkFlagRequired("url")
}

func runCall(cmd *cobra.Command, args []string) error {
	// Build injections from flags
	var injections []proxy.Injection

	if callBearer != "" {
		injections = append(injections, proxy.Injection{Style: "bearer", SecretKey: callBearer})
	}
	if callBasic != "" {
		injections = append(injections, proxy.Injection{Style: "basic", SecretKey: callBasic})
	}
	for _, h := range callHeaders {
		name, key, err := splitFlag(h, "header")
		if err != nil {
			return err
		}
		injections = append(injections, proxy.Injection{Style: "header", Target: name, SecretKey: key})
	}
	for _, q := range callQueries {
		param, key, err := splitFlag(q, "query")
		if err != nil {
			return err
		}
		injections = append(injections, proxy.Injection{Style: "query", Target: param, SecretKey: key})
	}
	for _, b := range callBodyFields {
		path, key, err := splitFlag(b, "body-field")
		if err != nil {
			return err
		}
		injections = append(injections, proxy.Injection{Style: "body", Target: path, SecretKey: key})
	}
	for _, f := range callFormFields {
		field, key, err := splitFlag(f, "form-field")
		if err != nil {
			return err
		}
		injections = append(injections, proxy.Injection{Style: "form", Target: field, SecretKey: key})
	}

	if len(injections) == 0 {
		return fmt.Errorf(
			"'agentsecrets call' is a credential proxy — it makes authenticated API calls by injecting secrets from your keychain.\n\n" +
				"You must specify at least one injection flag so AgentSecrets knows which credential to attach:\n\n" +
				"  --bearer SECRET_KEY           → Authorization: Bearer <value>\n" +
				"  --header Name=SECRET_KEY      → Custom header injection\n" +
				"  --query param=SECRET_KEY      → Query parameter injection\n" +
				"  --basic SECRET_KEY            → Basic auth (secret stored as user:pass)\n" +
				"  --body-field path=SECRET_KEY  → JSON body field injection\n" +
				"  --form-field key=SECRET_KEY   → Form field injection\n\n" +
				"Example: agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY\n\n" +
				"If this request doesn't need authentication, use curl instead — 'agentsecrets call' is only for requests that need credentials injected from the keychain.",
		)
	}

	// Load project config
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		ui.Error("No project configured — run 'agentsecrets init' first")
		return nil
	}

	// Create engine and execute
	engine, err := proxy.NewEngine(project.ProjectID)
	if err != nil {
		return fmt.Errorf("failed to initialize engine: %w", err)
	}

	var body []byte
	if callBody != "" {
		body = []byte(callBody)
	}

	result, err := engine.Execute(proxy.CallRequest{
		TargetURL:  callURL,
		Method:     callMethod,
		Body:       body,
		Injections: injections,
		AgentID:    "cli",
	})
	if err != nil {
		return fmt.Errorf("API call failed: %w", err)
	}

	// Print response (clean stdout for piping)
	fmt.Printf("HTTP %d\n\n%s\n", result.StatusCode, string(result.Body))
	return nil
}

// splitFlag parses "name=value" flag format.
func splitFlag(s string, flagName string) (string, string, error) {
	parts := strings.SplitN(s, "=", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("--%s must be in Name=SECRET_KEY format, got %q", flagName, s)
	}
	return parts[0], parts[1], nil
}
