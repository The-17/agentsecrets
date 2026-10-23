// Package gateway is the single owner of credential resolution mode.
//
// Every CLI surface that needs a secret (call, env, exec, status) asks this
// package where the credential comes from. Nothing else decides local vs
// cloud, and nothing else talks to the cloud resolver. That keeps the promise
// uniform: a command gets credentials the same way regardless of mode, and a
// new command inherits both modes by calling one function.
//
// Two transports live behind one interface:
//
//	local  — the OS keychain through the local proxy engine (offline)
//	cloud  — POST {resolver}/v1/resolve with a workload token, where the
//	         resolver substitutes {{KEY}} handles server-side
//
// Neither transport returns a plaintext secret to the CLI. Local injection
// happens inside the proxy process; cloud substitution happens inside the
// resolver. The CLI only ever holds key names.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	clierrors "github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/proxy"
)

// Mode is where credentials are resolved. It is a closed set: an unknown
// string cannot be constructed as a Mode, so no consumer can compare against a
// value that does not exist.
type Mode string

const (
	// ModeLocal resolves from the OS keychain through the local proxy.
	ModeLocal Mode = "local"
	// ModeCloud resolves through the AgentSecrets cloud resolver.
	ModeCloud Mode = "cloud"
)

// DefaultResolverURL is the cloud resolver host. It is a separate service from
// the control plane: api.agentsecrets.tech serves no /v1/* routes.
const DefaultResolverURL = "https://resolver.agentsecrets.tech"

// Env vars that select a mode. They mirror the MCP bridge and the Python SDK so
// one environment configures every surface.
const (
	envUseCloud   = "AGENTSECRETS_USE_CLOUD"
	envMode       = "AGENTSECRETS_MODE"
	envToken      = "AGENTSECRETS_TOKEN"
	envTokenFile  = "AGENTSECRETS_TOKEN_FILE"
	envResolver  = "AGENTSECRETS_CLOUD_RESOLVER_URL"
	envServerURL = "AGENTSECRETS_SERVER_URL"
)

// Selection records the resolved mode and why it won. The reason is shown in
// status output so a surprising mode is explainable rather than mysterious.
type Selection struct {
	Mode   Mode
	Source string
}

// Select resolves the effective mode.
//
// Precedence, highest first:
//
//  1. an explicit flag (--cloud / --local)
//  2. AGENTSECRETS_USE_CLOUD / AGENTSECRETS_MODE
//  3. the persisted preference (agentsecrets mode cloud|local)
//  4. a workload token in the environment, which only makes sense in cloud
//  5. local
//
// An explicit "local" choice outranks a token in the environment. Otherwise a
// stray AGENTSECRETS_TOKEN would silently move every command onto a billed
// cloud path after the user asked for local.
func Select(flag string) (Selection, error) {
	switch flag {
	case string(ModeCloud):
		return Selection{Mode: ModeCloud, Source: "flag"}, nil
	case string(ModeLocal):
		return Selection{Mode: ModeLocal, Source: "flag"}, nil
	case "":
		// fall through to env/config
	default:
		return Selection{}, fmt.Errorf("mode must be %q or %q, got %q", ModeLocal, ModeCloud, flag)
	}

	if v := strings.ToLower(strings.TrimSpace(os.Getenv(envMode))); v != "" {
		switch Mode(v) {
		case ModeCloud:
			return Selection{Mode: ModeCloud, Source: envMode}, nil
		case ModeLocal:
			return Selection{Mode: ModeLocal, Source: envMode}, nil
		default:
			return Selection{}, fmt.Errorf("%s must be %q or %q, got %q", envMode, ModeLocal, ModeCloud, v)
		}
	}

	if v := strings.ToLower(strings.TrimSpace(os.Getenv(envUseCloud))); v != "" {
		switch v {
		case "true", "1":
			return Selection{Mode: ModeCloud, Source: envUseCloud}, nil
		case "false", "0":
			return Selection{Mode: ModeLocal, Source: envUseCloud}, nil
		}
	}

	if stored := config.GetDefaultMode(); stored != "" {
		return Selection{Mode: Mode(stored), Source: "config"}, nil
	}

	if TokenFromEnv() != "" {
		return Selection{Mode: ModeCloud, Source: envToken}, nil
	}

	return Selection{Mode: ModeLocal, Source: "default"}, nil
}

// TokenFromEnv returns the workload token supplied by the environment, reading
// AGENTSECRETS_TOKEN and then the file named by AGENTSECRETS_TOKEN_FILE. The
// file indirection exists so a token never has to sit in a process listing or
// a client config.
func TokenFromEnv() string {
	if tok := strings.TrimSpace(os.Getenv(envToken)); tok != "" {
		return tok
	}
	path := strings.TrimSpace(os.Getenv(envTokenFile))
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ResolverURL returns the resolver base URL: env override, then a URL derived
// from the configured server, then the default resolver.
func ResolverURL() string {
	if v := strings.TrimSpace(os.Getenv(envResolver)); v != "" {
		return strings.TrimRight(v, "/")
	}
	// A self-hosted deployment may serve resolution itself. Only derive a
	// resolver host from an explicit server override; the default control plane
	// does not serve /v1/*.
	if v := strings.TrimSpace(os.Getenv(envServerURL)); v != "" {
		return strings.TrimRight(strings.TrimSuffix(strings.TrimRight(v, "/"), "/api"), "/")
	}
	return DefaultResolverURL
}

// ResolveError is a mode-specific failure the caller can surface verbatim. It
// carries the remediation the user needs, because a resolution failure without
// a next step is just noise.
//
// It also classifies itself into the CLI error taxonomy. A bad workload token
// or a blocked domain is an expected, actionable condition, not an unhandled
// crash, so the CLI must not answer it with "email support".
type ResolveError struct {
	Mode Mode
	Msg  string
	Err  error
	// Code is the CLI error code this failure maps to. Empty means
	// ErrUnauthorized, the most common cause of a resolver rejection.
	Code clierrors.ErrorCode
}

func (e *ResolveError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Mode, e.Msg, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Mode, e.Msg)
}

func (e *ResolveError) Unwrap() error { return e.Err }

// AsCLIError lets the root command render a resolution failure with its own
// code instead of collapsing it into ERR-999.
func (e *ResolveError) AsCLIError() *clierrors.CLIError {
	code := e.Code
	if code == "" {
		code = clierrors.ErrUnauthorized
	}
	return clierrors.New(code, e.Msg, e.Err)
}

// CallRequest is one credentialed HTTP call, expressed the same way in both
// modes. Injections name a secret key and a placement; the transport decides
// how to apply it.
type CallRequest struct {
	TargetURL  string
	Method     string
	Headers    map[string]string
	Body       []byte
	Injections []proxy.Injection
	AgentToken string
}

// CallResult is the sanitized upstream response. Body and headers are already
// redacted by whichever transport ran.
type CallResult struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
	Redacted   bool
	Via        Mode
}

// Call performs the request in the selected mode. This is the only entry point
// a command needs: it does not branch on mode itself.
func Call(req CallRequest, sel Selection) (*CallResult, error) {
	switch sel.Mode {
	case ModeLocal:
		res, err := proxy.CallViaProxy(proxy.CallRequest{
			TargetURL:  req.TargetURL,
			Method:     req.Method,
			Headers:    req.Headers,
			Body:       req.Body,
			Injections: req.Injections,
			AgentToken: req.AgentToken,
		})
		if err != nil {
			return nil, err
		}
		return &CallResult{
			StatusCode: res.StatusCode,
			Headers:    res.Headers,
			Body:       res.Body,
			Redacted:   containsPlaceholder(res.Body, res.Headers),
			Via:        ModeLocal,
		}, nil
	case ModeCloud:
		return callCloud(req)
	default:
		return nil, fmt.Errorf("unknown mode %q", sel.Mode)
	}
}

// resolveRequest mirrors the resolver's documented payload.
type resolveRequest struct {
	TargetURL string            `json:"target_url"`
	Method    string            `json:"method"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body,omitempty"`
	Scope     *resolveScope     `json:"scope,omitempty"`
}

type resolveScope struct {
	WorkspaceID string `json:"workspace_id,omitempty"`
	ProjectID   string `json:"project_id,omitempty"`
	Environment string `json:"environment,omitempty"`
}

type resolveResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Redacted   bool              `json:"redacted"`
}

// cloudTimeout bounds a resolver call. Upstream APIs can be slow, so this is
// generous; the local path has its own 60s client timeout.
const cloudTimeout = 60 * time.Second

// callCloud sends one request to the cloud resolver.
func callCloud(req CallRequest) (*CallResult, error) {
	token := strings.TrimSpace(req.AgentToken)
	if token == "" {
		token = TokenFromEnv()
	}
	if token == "" {
		return nil, &ResolveError{
			Mode: ModeCloud,
			Msg:  "cloud resolution needs a workload token, and none was provided",
			Err:  fmt.Errorf("set AGENTSECRETS_TOKEN (or AGENTSECRETS_TOKEN_FILE), or mint one with 'agentsecrets agent token issue'"),
		}
	}

	payload, err := buildResolveRequest(req)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("cloud: failed to encode request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cloudTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ResolverURL()+"/v1/resolve", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("cloud: failed to build resolver request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := (&http.Client{Timeout: cloudTimeout}).Do(httpReq)
	if err != nil {
		return nil, &ResolveError{
			Mode: ModeCloud,
			Msg:  "could not reach the cloud resolver at " + ResolverURL(),
			Err:  err,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, decodeResolverError(resp)
	}

	var out resolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("cloud: resolver returned an unreadable response: %w", err)
	}

	headers := make(map[string][]string, len(out.Headers))
	for k, v := range out.Headers {
		headers[k] = []string{v}
	}

	return &CallResult{
		StatusCode: out.StatusCode,
		Headers:    headers,
		Body:       []byte(out.Body),
		Redacted:   out.Redacted,
		Via:        ModeCloud,
	}, nil
}

// buildResolveRequest translates injection specs into {{KEY}} handles. The
// resolver substitutes handles in header values and the body only, so basic
// auth and query placement are rejected with the local fallback named rather
// than silently mangled.
func buildResolveRequest(req CallRequest) (*resolveRequest, error) {
	headers := make(map[string]string, len(req.Headers)+len(req.Injections))
	for k, v := range req.Headers {
		headers[k] = v
	}

	body := string(req.Body)
	var bodyObj map[string]interface{}
	bodyParsed := false
	bodyDirty := false
	formDirty := false

	for _, inj := range req.Injections {
		handle := "{{" + inj.SecretKey + "}}"
		switch inj.Style {
		case "bearer":
			headers["Authorization"] = "Bearer " + handle
		case "header":
			if inj.Target == "" {
				return nil, fmt.Errorf("header injection requires a target")
			}
			headers[inj.Target] = handle
		case "body":
			if inj.Target == "" {
				return nil, fmt.Errorf("body injection requires a path")
			}
			if !bodyParsed {
				bodyObj = map[string]interface{}{}
				if strings.TrimSpace(body) != "" {
					if err := json.Unmarshal([]byte(body), &bodyObj); err != nil {
						return nil, fmt.Errorf("body injection needs a JSON object body in cloud mode: %w", err)
					}
				}
				bodyParsed = true
			}
			if err := proxy.SetNested(bodyObj, inj.Target, handle); err != nil {
				return nil, err
			}
			bodyDirty = true
			headers["Content-Type"] = "application/json"
		case "form":
			if inj.Target == "" {
				return nil, fmt.Errorf("form injection requires a field")
			}
			// Handled after the loop so multiple form fields merge into one body.
			formDirty = true
			headers["Content-Type"] = "application/x-www-form-urlencoded"
		case "basic":
			return nil, &ResolveError{
				Mode: ModeCloud,
				Msg:  "basic auth cannot be injected in cloud mode (the resolver substitutes handles, it cannot base64-encode)",
				Err:  fmt.Errorf("run this call with --local, or store the pre-encoded value in a header"),
			}
		case "query":
			return nil, &ResolveError{
				Mode: ModeCloud,
				Msg:  "query parameters cannot be injected in cloud mode (handles substitute in headers and body only)",
				Err:  fmt.Errorf("run this call with --local"),
			}
		default:
			return nil, fmt.Errorf("unknown injection style %q", inj.Style)
		}
	}

	if bodyDirty {
		merged, err := json.Marshal(bodyObj)
		if err != nil {
			return nil, fmt.Errorf("cloud: failed to encode body: %w", err)
		}
		body = string(merged)
	}
	if formDirty {
		merged, err := mergeFormBody(body, req.Injections)
		if err != nil {
			return nil, err
		}
		body = merged
	}

	return &resolveRequest{
		TargetURL: req.TargetURL,
		Method:    req.Method,
		Headers:   headers,
		Body:      body,
	}, nil
}

// mergeFormBody applies every form injection to the existing urlencoded body.
func mergeFormBody(body string, injections []proxy.Injection) (string, error) {
	values := map[string][]string{}
	if strings.TrimSpace(body) != "" {
		if !strings.Contains(body, "=") {
			return "", &ResolveError{
				Mode: ModeCloud,
				Msg:  "form injection cannot merge into a non-urlencoded body",
				Err:  fmt.Errorf("use --local, or send an empty or urlencoded body"),
			}
		}
		for _, pair := range strings.Split(body, "&") {
			if pair == "" {
				continue
			}
			k, v, _ := strings.Cut(pair, "=")
			values[k] = append(values[k], v)
		}
	}
	for _, inj := range injections {
		if inj.Style == "form" {
			values[inj.Target] = []string{"{{" + inj.SecretKey + "}}"}
		}
	}
	var parts []string
	for k, vs := range values {
		for _, v := range vs {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, "&"), nil
}

// decodeResolverError turns a resolver error body into an actionable error.
func decodeResolverError(resp *http.Response) error {
	var payload struct {
		ErrorCode string `json:"error_code"`
		Message   string `json:"message"`
		Error     string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&payload)

	msg := payload.Message
	if msg == "" {
		msg = payload.Error
	}
	if msg == "" {
		msg = fmt.Sprintf("resolver returned HTTP %d", resp.StatusCode)
	}
	if payload.ErrorCode != "" {
		msg = payload.ErrorCode + ": " + msg
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return &ResolveError{
			Mode: ModeCloud,
			Msg:  msg,
			Err:  fmt.Errorf("the workload token is invalid, expired, or revoked"),
			Code: clierrors.ErrUnauthorized,
		}
	case http.StatusPaymentRequired:
		return &ResolveError{
			Mode: ModeCloud,
			Msg:  msg,
			Err:  fmt.Errorf("cloud resolution is a billed entitlement; check the plan for this workspace"),
			Code: clierrors.ErrForbidden,
		}
	case http.StatusTooManyRequests:
		return &ResolveError{
			Mode: ModeCloud,
			Msg:  msg,
			Err:  fmt.Errorf("monthly cloud resolution quota is exhausted"),
			Code: clierrors.ErrForbidden,
		}
	case http.StatusForbidden:
		return &ResolveError{Mode: ModeCloud, Msg: msg, Code: clierrors.ErrForbidden}
	}
	return &ResolveError{Mode: ModeCloud, Msg: msg, Code: clierrors.ErrServerInternal}
}

// containsPlaceholder reports whether a response already carries the redaction
// marker, so callers can report redaction without re-deriving it.
func containsPlaceholder(body []byte, headers map[string][]string) bool {
	if strings.Contains(string(body), proxy.RedactionPlaceholder) {
		return true
	}
	for _, vs := range headers {
		for _, v := range vs {
			if strings.Contains(v, proxy.RedactionPlaceholder) {
				return true
			}
		}
	}
	return false
}

// SecretsForEnv fetches every secret in scope for `env` and `exec`.
//
// The router decides who handles the request and nothing else:
//
//   - cloud: this package fetches from the workload-env endpoint, passing
//     environment through so `--env qa` narrows the same way it does locally.
//     An empty environment keeps the token's own binding.
//   - local: the caller's local resolver runs unchanged, so the keychain
//     session, audit, and masking path stay exactly as they are.
//
// The local callback exists because local resolution needs the caller's
// keychain-auth session and project context. Passing it in keeps the mode
// decision here without duplicating local behavior in this package.
func SecretsForEnv(sel Selection, local func() (map[string]string, error), environment string) (map[string]string, error) {
	switch sel.Mode {
	case ModeCloud:
		token := TokenFromEnv()
		if token == "" {
			return nil, &ResolveError{
				Mode: ModeCloud,
				Msg:  "cloud resolution needs a workload token, and none was provided",
				Err:  fmt.Errorf("set AGENTSECRETS_TOKEN (or AGENTSECRETS_TOKEN_FILE)"),
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		secrets, err := api.FetchWorkloadEnv(ctx, config.GetServerURL(), token, environment)
		if err != nil {
			return nil, &ResolveError{Mode: ModeCloud, Msg: "cloud resolution failed", Err: err}
		}
		return secrets, nil
	case ModeLocal:
		if local == nil {
			return nil, errors.New("gateway: local resolution callback is required")
		}
		return local()
	default:
		return nil, fmt.Errorf("unknown mode %q", sel.Mode)
	}
}
