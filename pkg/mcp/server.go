// Package mcp implements a Model Context Protocol server exposing credential, audit, and context tools for AI agents.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/secrets"
	"github.com/The-17/agentsecrets/pkg/workspaces"

	"github.com/The-17/agentsecrets/pkg/telemetry"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Deps holds the shared services an MCP Server uses. Any nil field is lazily
// constructed on first use (see the get* methods), so tests and standalone
// callers can pass a zero Deps.
type Deps struct {
	API        *api.Client
	Workspaces *workspaces.Service
	Secrets    *secrets.Service
}

// Server holds the dependencies shared across MCP tool handlers. It replaces the
// former package-level service globals, so handler state is explicit and each
// Server instance is self-contained.
type Server struct {
	apiClient        *api.Client
	workspaceService *workspaces.Service
	secretsService   *secrets.Service

	// tiers records the permission tier of every registered tool, so the
	// status tool can report the real state instead of a claim. See tiers.go.
	tiers map[string]Tier
}

// NewServer creates an MCP server with the full AgentSecrets tool surface using
// zero dependencies (all lazily constructed). Retained for tests and callers
// that don't share the CLI's services.
func NewServer(version string) *server.MCPServer {
	return newServer(version, Deps{})
}

// newServer builds the MCP server, wiring every tool handler to a method on a
// Server constructed from deps.
func newServer(version string, deps Deps) *server.MCPServer {
	srv := &Server{
		apiClient:        deps.API,
		workspaceService: deps.Workspaces,
		secretsService:   deps.Secrets,
		tiers:            make(map[string]Tier),
	}

	s := server.NewMCPServer(
		"AgentSecrets",
		version,
		server.WithToolCapabilities(false),
	)

	// Every tool is registered through s.add, which enforces its tier. A tool
	// cannot reach the surface without declaring one. See tiers.go.
	//
	// --- Credential Operations (read: use a credential, never mutate one) ---
	srv.add(s, read(apiCallTool(), srv.handleAPICall))
	srv.add(s, read(listKeysTool(), srv.handleListKeys))
	srv.add(s, read(checkKeyTool(), srv.handleCheckKey))
	srv.add(s, read(getCoverageTool(), srv.handleGetCoverage))

	// --- Context Management ---
	srv.add(s, read(getStatusTool(), srv.handleGetStatus))
	srv.add(s, read(getEnvironmentTool(), srv.handleGetEnvironment))
	srv.add(s, write(switchEnvironmentTool(), srv.handleSwitchEnvironment))
	srv.add(s, write(pullSecretsTool(), srv.handlePullSecrets))
	srv.add(s, read(diffSecretsTool(), srv.handleDiffSecrets))
	srv.add(s, read(diffEnvironmentsTool(), srv.handleDiffEnvironments))

	// --- Audit & Observability ---
	srv.add(s, read(getProxyLogsTool(), srv.handleGetProxyLogs))
	srv.add(s, read(getBlockedRequestsTool(), srv.handleGetBlockedRequests))
	srv.add(s, read(getRedactionEventsTool(), srv.handleGetRedactionEvents))
	srv.add(s, read(getAuditSummaryTool(), srv.handleGetAuditSummary))

	// --- Agent Identity ---
	srv.add(s, read(getAgentIdentityTool(), srv.handleGetAgentIdentity))
	srv.add(s, read(listAgentTokensTool(), srv.handleListAgentTokens))

	// --- Allowlist (read only: editing it widens access, which is exactly
	// what an injected instruction asks for) ---
	srv.add(s, read(checkDomainTool(), srv.handleCheckDomain))
	srv.add(s, read(getAllowlistTool(), srv.handleGetAllowlist))

	// --- Key Rotation ---
	srv.add(s, destructive(rotateKeyTool(), srv.handleRotateKey))

	// --- Secret Provisioning ---
	//
	// secret_store is deliberately NOT registered. Value-blind creation is a
	// code-facing capability (CLI prompt, --stdin, --generate, --from-command,
	// and the Python SDK), where a human wrote the code and holds the token.
	// On a model-facing surface the safest create path is no create path: a
	// minted credential is durable, and prompt injection is the threat, not
	// value leakage. The handler is kept so the capability can return behind an
	// explicit human decision, but it is not reachable by an agent.
	//
	// See tiers.go and the decision artifact "permission tiers enforced at
	// registration".

	return s
}

// Serve starts the MCP server on stdio (for Claude Desktop, Cursor, etc), using
// the provided shared services.
func Serve(version string, deps Deps) error {
	telemetry.RecordIntegration("mcp")
	s := newServer(version, deps)
	return server.ServeStdio(s)
}

// --- Tool definitions ---

func apiCallTool() mcp.Tool {
	return mcp.NewTool("api_call",
		mcp.WithDescription(
			"Make an authenticated API call. Credentials are injected from the OS keychain — "+
				"you will NEVER see the actual secret values. "+
				"Use list_keys first to discover available key names.",
		),
		mcp.WithString("url",
			mcp.Required(),
			mcp.Description("Target API URL (e.g. https://api.stripe.com/v1/charges)"),
		),
		mcp.WithString("method",
			mcp.Description("HTTP method: GET, POST, PUT, PATCH, DELETE. Default: GET"),
		),
		mcp.WithString("body",
			mcp.Description("Request body as a JSON string"),
		),
		mcp.WithObject("headers",
			mcp.Description("Extra request headers as key-value pairs"),
		),
		mcp.WithObject("injections",
			mcp.Required(),
			mcp.Description(
				"Map of injection_spec to secret_key_name. "+
					"Specs: \"bearer\", \"basic\", \"header:X-Name\", \"query:param\", \"body:json.path\", \"form:field\". "+
					"Example: {\"bearer\": \"STRIPE_KEY\"} or {\"header:X-API-Key\": \"API_KEY\"}",
			),
		),
		mcp.WithObject("capture",
			mcp.Description(
				"Optional: store a field of the response as a secret and replace it in the returned body with [REDACTED_BY_AGENTSECRETS]. "+
					"Use when the call MINTS a credential (e.g. POST /keys returns a new key) so the value never enters your context. "+
					"Keys: key_name (required), extract (required: dot-separated JSON path to the field to store and redact, e.g. \"data.key\").",
			),
		),
	)
}

// --- Handlers ---

func (s *Server) handleAPICall(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()

	// Required: url
	url, ok := args["url"].(string)
	if !ok || url == "" {
		return mcp.NewToolResultError("missing required parameter: url"), nil
	}

	// Optional: method (default GET)
	method, _ := args["method"].(string)
	if method == "" {
		method = "GET"
	}

	// Optional: body
	var body []byte
	if bodyStr, ok := args["body"].(string); ok && bodyStr != "" {
		body = []byte(bodyStr)
	}

	// Optional: headers
	headers := make(map[string]string)
	if hdrs, ok := args["headers"].(map[string]interface{}); ok {
		for k, v := range hdrs {
			if s, ok := v.(string); ok {
				headers[k] = s
			}
		}
	}

	// Required: injections
	rawInjections, ok := args["injections"].(map[string]interface{})
	if !ok || len(rawInjections) == 0 {
		return mcp.NewToolResultError("missing required parameter: injections — provide at least one injection like {\"bearer\": \"SECRET_KEY\"}"), nil
	}

	injections, err := parseInjections(rawInjections)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid injections: %v", err)), nil
	}

	// Optional: capture — store a response field as a secret and redact it.
	var capture struct {
		keyName string
		extract string
	}
	if capRaw, ok := args["capture"].(map[string]interface{}); ok && capRaw != nil {
		capture.keyName = strings.TrimSpace(mustString(capRaw["key_name"]))
		capture.extract = strings.TrimSpace(mustString(capRaw["extract"]))
		if capture.keyName == "" {
			return mcp.NewToolResultError("capture requires key_name"), nil
		}
		if capture.extract == "" {
			return mcp.NewToolResultError("capture requires extract (dot-separated JSON path to the field to store and redact)"), nil
		}
	}

	// Execute via the proxy daemon
	result, err := proxy.CallViaProxy(proxy.CallRequest{
		TargetURL:  url,
		Method:     method,
		Headers:    headers,
		Body:       body,
		Injections: injections,
		AgentID:    "mcp",
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("API call failed: %v", err)), nil
	}

	// Format response.
	var caption string
	if capture.keyName != "" {
		value, capErr := secrets.ExtractJSONPath(result.Body, capture.extract)
		if capErr != nil {
			// Store nothing and do not return the body, so the unredacted value
			// never reaches the model.
			return mcp.NewToolResultError(fmt.Sprintf("capture failed: %v — the API call succeeded but nothing was stored, so the body is not returned", capErr)), nil
		}
		meta, capErr := s.getSecretsService().SetProvisioned(capture.keyName, value, "")
		if capErr != nil {
			// Safe to surface: the store error never carries a secret value.
			return mcp.NewToolResultError(fmt.Sprintf("capture failed to store %s: %v — the body is not returned", capture.keyName, capErr)), nil
		}
		result.Body = redactValue(result.Body, value)
		caption = fmt.Sprintf(
			"Secret stored as %s (environment %s, %d bytes, fingerprint %s). The value was replaced with [REDACTED_BY_AGENTSECRETS] in the body below.\n\n",
			meta.Key, meta.Environment, meta.Length, meta.Fingerprint,
		)
	}

	response := fmt.Sprintf("HTTP %d\n%s%s", result.StatusCode, caption, string(result.Body))
	return mcp.NewToolResultText(response), nil
}

// mustString type-asserts an args value to a bare string, returning "" otherwise.
func mustString(v interface{}) string {
	s, _ := v.(string)
	return s
}

// redactValue replaces every occurrence of value in body with the proxy
// redaction placeholder so a freshly minted credential cannot survive in a
// returned body.
func redactValue(body []byte, value string) []byte {
	if value == "" {
		return body
	}
	return bytes.ReplaceAll(body, []byte(value), []byte(proxy.RedactionPlaceholder))
}

// --- Shared Helpers ---

func (s *Server) getAPIClient() *api.Client {
	if s.apiClient != nil {
		return s.apiClient
	}
	return auth.NewAuthenticatedClient()
}

func (s *Server) getWorkspaceService() *workspaces.Service {
	if s.workspaceService != nil {
		return s.workspaceService
	}
	return workspaces.NewService(s.getAPIClient())
}

func (s *Server) getSecretsService() *secrets.Service {
	if s.secretsService != nil {
		return s.secretsService
	}
	return secrets.NewService(s.getAPIClient())
}

// jsonResult marshals v to indented JSON and returns it as a tool result.
func jsonResult(v interface{}) (*mcp.CallToolResult, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal response: %v", err)), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}

// parseInjections converts the agent's map format into proxy.Injection structs.
//
// Supported formats:
//
//	"bearer":          "KEY"  → {Style: "bearer", SecretKey: "KEY"}
//	"basic":           "KEY"  → {Style: "basic",  SecretKey: "KEY"}
//	"header:X-Name":   "KEY"  → {Style: "header", Target: "X-Name", SecretKey: "KEY"}
//	"query:param":     "KEY"  → {Style: "query",  Target: "param",  SecretKey: "KEY"}
//	"body:path.field": "KEY"  → {Style: "body",   Target: "path.field", SecretKey: "KEY"}
//	"form:field":      "KEY"  → {Style: "form",   Target: "field",  SecretKey: "KEY"}
func parseInjections(raw map[string]interface{}) ([]proxy.Injection, error) {
	var injections []proxy.Injection

	for spec, val := range raw {
		secretKey, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("injection value for %q must be a string (secret key name)", spec)
		}

		inj := proxy.Injection{SecretKey: secretKey}

		// Parse "style" or "style:target"
		parts := strings.SplitN(spec, ":", 2)
		style := strings.ToLower(parts[0])

		switch style {
		case "bearer", "basic":
			inj.Style = style
		case "header", "query", "body", "form":
			if len(parts) != 2 || parts[1] == "" {
				return nil, fmt.Errorf("%s injection requires a target — use %q format", style, style+":target_name")
			}
			inj.Style = style
			inj.Target = parts[1]
		default:
			validStyles := "bearer, basic, header:name, query:param, body:path, form:field"
			return nil, fmt.Errorf("unknown injection style %q — valid styles: %s", spec, validStyles)
		}

		injections = append(injections, inj)
	}

	return injections, nil
}

// ParseInjectionsJSON parses a JSON string of injections into proxy.Injection structs.
// Exported for testing.
func ParseInjectionsJSON(jsonStr string) ([]proxy.Injection, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil, fmt.Errorf("invalid injections JSON: %w", err)
	}
	return parseInjections(raw)
}
