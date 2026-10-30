package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/gateway"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var (
	callURL        string
	callMethod     string
	callBody       string
	callBearer     string
	callBasic      string
	callToken      string
	callHeaders    []string // "X-API-Key=SECRET_NAME"
	callQueries    []string // "api_key=SECRET_NAME"
	callBodyFields []string // "json.path=SECRET_NAME"
	callFormFields []string // "field=SECRET_NAME"
	callSetHeaders []string // "Name=Value" plain headers (non-secret)
	callOutput     string   // "text" (default) or "json"
	callMode       string   // "" (router decides), "cloud", or "local"
)

var callCmd = &cobra.Command{
	Use:   "call",
	Short: "Make an authenticated API call (credentials never exposed)",
	Long: `Make a one-shot authenticated API call. Credentials are resolved
	by the mode router and injected into the request — they are never printed
	or exposed to your AI assistant.

	Local mode (default): the OS keychain resolves the secret inside the local
	proxy, so allowlist, policy, SSRF, redaction, and audit all run as usual.
	Cloud mode: the cloud resolver substitutes {{KEY}} handles server-side.

	Mode precedence: --cloud/--local or --mode, then AGENTSECRETS_MODE or
	AGENTSECRETS_USE_CLOUD, then the saved mode ('agentsecrets mode'), then
	local.

	Examples:
	# Bearer token (most common)
	agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY

	# Force the cloud resolver for one call
	agentsecrets call --cloud --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY

	# POST with body
	agentsecrets call --url https://api.stripe.com/v1/charges \
		--method POST --bearer STRIPE_KEY \
		--body '{"amount":1000,"currency":"usd","source":"tok_visa"}'

	# Custom header
	agentsecrets call --url https://api.example.com/data \
		--header X-API-Key=MY_KEY

	# Plain (non-secret) header. Use for Content-Type when you need one other
	# than the default: a JSON body is sent as application/json automatically.
	agentsecrets call --url https://api.example.com/data \
		--bearer MY_KEY --body '{"text":"hi"}' \
		--set-header Content-Type=application/json
`,
	Aliases:      []string{"calls"},
	SilenceUsage: true,
	RunE:         runCall,
}

func init() {
	callCmd.Flags().StringVar(&callURL, "url", "", "Target API URL (required)")
	callCmd.Flags().StringVar(&callMethod, "method", "GET", "HTTP method")
	callCmd.Flags().StringVar(&callBody, "body", "", "Request body (JSON string)")
	callCmd.Flags().StringVar(&callBearer, "bearer", "", "Bearer token secret key name")
	callCmd.Flags().StringVar(&callBasic, "basic", "", "Basic auth secret key name")
	callCmd.Flags().StringVar(&callToken, "token", "", "Agent token (optional, or reads AS_AGENT_TOKEN)")
	callCmd.Flags().StringArrayVar(&callHeaders, "header", nil, "Header injection: HeaderName=SECRET_KEY (repeatable)")
	callCmd.Flags().StringArrayVar(&callQueries, "query", nil, "Query injection: param=SECRET_KEY (repeatable)")
	callCmd.Flags().StringArrayVar(&callBodyFields, "body-field", nil, "Body injection: json.path=SECRET_KEY (repeatable)")
	callCmd.Flags().StringArrayVar(&callFormFields, "form-field", nil, "Form injection: field=SECRET_KEY (repeatable)")
	callCmd.Flags().StringArrayVar(&callSetHeaders, "set-header", nil, "Plain header: Name=Value, no secret lookup (repeatable)")
	callCmd.Flags().StringVar(&callOutput, "output", "text", "Output format: text or json")
	callCmd.Flags().StringVar(&callMode, "mode", "", "Resolution mode: local or cloud (default: router decides)")
	callCmd.Flags().Bool("cloud", false, "Resolve through the cloud resolver for this call (shorthand for --mode cloud)")
	callCmd.Flags().Bool("local", false, "Resolve from the local keychain for this call (shorthand for --mode local)")
	_ = callCmd.MarkFlagRequired("url")

	_ = callCmd.RegisterFlagCompletionFunc("bearer", autocompleteSecretKeys)
	_ = callCmd.RegisterFlagCompletionFunc("basic", autocompleteSecretKeys)
}

func runCall(cmd *cobra.Command, args []string) error {
	switch callOutput {
	case "", outputText, outputJSON:
	default:
		return fmt.Errorf("--output must be %q or %q, got %q", outputText, outputJSON, callOutput)
	}

	selection, err := resolveCallMode(cmd)
	if err != nil {
		return err
	}

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

	// Plain headers. These are not secret lookups: they exist so a caller can
	// set Content-Type and similar. Protocol headers stay reserved.
	headers, err := parsePlainHeaders(callSetHeaders)
	if err != nil {
		return err
	}

	if len(injections) == 0 {
		return errors.WithSuggestions(errors.ErrUsage,
			"'agentsecrets call' is a credential proxy — it makes authenticated API calls by injecting secrets from your keychain.\n\n"+
				"You must specify at least one injection flag so AgentSecrets knows which credential to attach:\n\n"+
				"  --bearer SECRET_KEY           → Authorization: Bearer <value>\n"+
				"  --header Name=SECRET_KEY      → Custom header injection\n"+
				"  --query param=SECRET_KEY      → Query parameter injection\n"+
				"  --basic SECRET_KEY            → Basic auth (secret stored as user:pass)\n"+
				"  --body-field path=SECRET_KEY  → JSON body field injection\n"+
				"  --form-field key=SECRET_KEY   → Form field injection\n\n"+
				"Example: agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY\n\n"+
				"If this request doesn't need authentication, use curl instead — 'agentsecrets call' is only for requests that need credentials injected from the keychain.",
			nil,
			"add one injection flag, e.g. --bearer SECRET_KEY",
		)
	}

	var body []byte
	if callBody != "" {
		body = []byte(callBody)
	}

	callStart := time.Now()
	result, err := gateway.Call(gateway.CallRequest{
		TargetURL:  callURL,
		Method:     callMethod,
		Headers:    headers,
		Body:       body,
		Injections: injections,
		AgentToken: callToken,
	}, selection)
	durationMs := time.Since(callStart).Milliseconds()
	if err != nil {
		// The transport failed before any HTTP response (e.g. proxy unreachable).
		if callOutput == outputJSON {
			return emitCallJSON(callResultJSON{
				Headers:    map[string][]string{},
				DurationMs: durationMs,
				Error:      err.Error(),
			})
		}
		return fmt.Errorf("API call failed: %w", err)
	}

	// Structured output: emit the full envelope as a single JSON object on
	// stdout. Header values are redacted by the engine (redactResponse) exactly
	// like the body, so this is safe to hand to a programmatic consumer or an AI
	// agent. Error semantics mirror text mode (a non-empty "error" is populated
	// under the same conditions text mode prints one), so a consumer maps errors
	// the same way whether it reads stderr or the envelope.
	if callOutput == outputJSON {
		return emitCallJSON(buildCallJSON(result, durationMs))
	}

	if result.StatusCode >= 400 {
		var errData struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(result.Body, &errData); err == nil {
			msg := errData.Message
			if msg == "" {
				msg = errData.Error
			}
			if msg != "" {
				fmt.Fprintln(os.Stderr, ui.ErrorStyle.Render("x "+msg))
				// Message already rendered above; return a silent coded exit so
				// deferred cleanup/telemetry in Execute still run.
				return &ExitError{Code: 1, Silent: true}
			}
		}
		fmt.Fprintf(os.Stderr, "%s\n%s\n", ui.ErrorStyle.Render(fmt.Sprintf("x API call failed with HTTP %d:", result.StatusCode)), string(result.Body))
		return &ExitError{Code: 1, Silent: true}
	}

	// Print response (clean stdout for piping)
	fmt.Printf("HTTP %d\n\n%s\n", result.StatusCode, string(result.Body))
	return nil
}

// resolveCallMode applies the flag layer and asks the router for the rest.
// --cloud/--local are shorthands for --mode; passing both is a usage error
// rather than a silent winner. It is separate from runCall so the middleware
// can make the same decision before any keychain work starts.
func resolveCallMode(cmd *cobra.Command) (gateway.Selection, error) {
	flagMode := callMode
	cloudFlag, _ := cmd.Flags().GetBool("cloud")
	localFlag, _ := cmd.Flags().GetBool("local")
	if cloudFlag && localFlag {
		return gateway.Selection{}, errors.New(errors.ErrUsage, "--cloud and --local are mutually exclusive", nil)
	}
	if cloudFlag {
		flagMode = string(gateway.ModeCloud)
	}
	if localFlag {
		flagMode = string(gateway.ModeLocal)
	}
	sel, err := gateway.Select(flagMode)
	if err != nil {
		return gateway.Selection{}, err
	}
	return sel, nil
}

// Output format values for --output.
const (
	outputText = "text"
	outputJSON = "json"
)

// parsePlainHeaders turns repeatable --set-header Name=Value flags into a
// header map for CallRequest.Headers. It rejects the reserved X-AS-* prefix so
// a caller cannot rewrite the proxy protocol itself.
func parsePlainHeaders(values []string) (map[string]string, error) {
	headers := make(map[string]string, len(values))
	for _, h := range values {
		name, value, ok := strings.Cut(h, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" || value == "" {
			return nil, fmt.Errorf("--set-header must be Name=Value, got %q", h)
		}
		if strings.HasPrefix(strings.ToLower(name), "x-as-") {
			return nil, fmt.Errorf("--set-header cannot set reserved X-AS-* headers (%q)", name)
		}
		headers[name] = value
	}
	return headers, nil
}

// splitFlag parses "name=value" flag format.
func splitFlag(s string, flagName string) (string, string, error) {
	parts := strings.SplitN(s, "=", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("--%s must be in Name=SECRET_KEY format, got %q", flagName, s)
	}
	return parts[0], parts[1], nil
}

// callResultJSON is the stable, machine-readable envelope emitted by
// `agentsecrets call --output json`. Every field is safe to expose: body and
// header values are redacted upstream by the proxy engine (redactResponse), so
// a resolved secret value can never appear here. The SDK/agent receives secret
// key *names* only and consumes this shape; keep it backward-compatible.
type callResultJSON struct {
	Status     int                 `json:"status"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body"`
	Redacted   bool                `json:"redacted"`
	DurationMs int64               `json:"duration_ms"`
	Error      string              `json:"error,omitempty"`
}

// buildCallJSON converts a proxy CallResult into the JSON envelope. It mirrors
// text mode's error semantics: a >= 400 status populates "error" (from the
// upstream JSON error/message when present, else a generic HTTP summary) so a
// programmatic consumer branches identically to a stderr reader.
func buildCallJSON(result *gateway.CallResult, durationMs int64) callResultJSON {
	headers := result.Headers
	if headers == nil {
		headers = map[string][]string{}
	}

	body := string(result.Body)

	// Both transports redact the body and header values, so a response can
	// carry a redacted header (e.g. an echoed Set-Cookie) with an otherwise
	// clean body. The transports already report this; trust their verdict and
	// fall back to scanning for older callers that build a result by hand.
	redacted := result.Redacted
	if !redacted {
		redacted = strings.Contains(body, proxy.RedactionPlaceholder)
		for _, vals := range headers {
			if redacted {
				break
			}
			for _, v := range vals {
				if strings.Contains(v, proxy.RedactionPlaceholder) {
					redacted = true
					break
				}
			}
		}
	}

	out := callResultJSON{
		Status:     result.StatusCode,
		Headers:    headers,
		Body:       body,
		Redacted:   redacted,
		DurationMs: durationMs,
	}

	if result.StatusCode >= 400 {
		var errData struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(result.Body, &errData); err == nil {
			if msg := errData.Message; msg != "" {
				out.Error = msg
			} else if errData.Error != "" {
				out.Error = errData.Error
			}
		}
		if out.Error == "" {
			out.Error = fmt.Sprintf("HTTP %d", result.StatusCode)
		}
	}

	return out
}

// emitCallJSON writes the envelope as a single line of JSON to stdout. On a
// >= 400 upstream status it also returns a silent coded exit so the process
// exit status still signals failure (matching text mode) while stdout stays
// clean, parseable JSON.
func emitCallJSON(out callResultJSON) error {
	enc, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("failed to encode JSON output: %w", err)
	}
	fmt.Println(string(enc))
	if out.Status >= 400 || out.Error != "" {
		return &ExitError{Code: 1, Silent: true}
	}
	return nil
}
