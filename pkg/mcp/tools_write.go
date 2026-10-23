package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/secrets"
	"github.com/mark3labs/mcp-go/mcp"
)

// --- Tool Definitions ---

func switchEnvironmentTool() mcp.Tool {
	return mcp.NewTool("switch_environment",
		mcp.WithDescription(
			"⚠️ IMPORTANT: This changes the active environment (development, staging, production) "+
				"which affects which secrets the proxy resolves. Always confirm with the user in chat before calling this tool.",
		),
		mcp.WithString("environment",
			mcp.Required(),
			mcp.Description("The target environment to switch to (development, staging, or production)"),
		),
	)
}

func pullSecretsTool() mcp.Tool {
	return mcp.NewTool("pull_secrets",
		mcp.WithDescription(
			"⚠️ IMPORTANT: This overwrites local secrets (in .env and the OS keychain) with values fetched from the cloud. "+
				"Always confirm with the user in chat before calling this tool.",
		),
		mcp.WithString("environment",
			mcp.Description("Optional: The environment to pull secrets for. Defaults to active environment."),
		),
	)
}

func rotateKeyTool() mcp.Tool {
	return mcp.NewTool("rotate_key",
		mcp.WithDescription(
			"⚠️ IMPORTANT: This permanently deletes a secret key from the current environment (cloud, local .env, and OS keychain). "+
				"Always confirm with the user in chat before calling this tool.",
		),
		mcp.WithString("key_name",
			mcp.Required(),
			mcp.Description("The name of the secret key to delete/rotate (e.g. STRIPE_KEY)"),
		),
		mcp.WithString("environment",
			mcp.Description("Optional: The environment to rotate the key in. Defaults to active environment."),
		),
	)
}

func secretStoreTool() mcp.Tool {
	return mcp.NewTool("secret_store",
		mcp.WithDescription(
			"Store a secret WITHOUT the value ever entering your context or the command line. "+
				"⚠️ IMPORTANT: This creates or updates a stored credential. Confirm with the user in chat before calling this tool. "+
				"The value always comes from a source you name, never from you: "+
				"source=generate mints a random value in-process; "+
				"source=command captures a command's stdout (for example a provider CLI that mints a key); "+
				"source=http fetches a URL. "+
				"Returns only {status, key_name, environment, length, fingerprint}. The value is never returned and is never a parameter.",
		),
		mcp.WithString("key_name",
			mcp.Required(),
			mcp.Description("Name of the secret key to create or update (e.g. STRIPE_KEY)"),
		),
		mcp.WithString("source",
			mcp.Required(),
			mcp.Description("Where the value comes from: generate | command | http"),
		),
		mcp.WithString("environment",
			mcp.Description("Optional: environment to store in. Defaults to the active environment."),
		),
		mcp.WithString("command",
			mcp.Description("source=command: shell command whose stdout is the value. Its output is never logged or returned."),
		),
		mcp.WithString("url",
			mcp.Description("source=http: URL to GET the value from."),
		),
		mcp.WithObject("headers",
			mcp.Description("source=http: extra request headers as key-value pairs."),
		),
		mcp.WithNumber("length",
			mcp.Description("source=generate: value length in bytes. Default 32."),
		),
		mcp.WithString("extract",
			mcp.Description("Optional: dot-separated JSON path to the field that holds the value (source=command or source=http), e.g. \"data.key\"."),
		),
	)
}

// --- Handlers ---

func (s *Server) handleSwitchEnvironment(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	env, _ := args["environment"].(string)
	if env == "" {
		return mcp.NewToolResultError("missing required parameter: environment"), nil
	}

	env, err := config.ParseEnvironment(env)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Load and update project config
	pc, err := config.LoadProjectConfig()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to load project config: %v", err)), nil
	}
	oldEnv := pc.Environment
	pc.Environment = env
	if err := config.SaveProjectConfig(pc); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to save project config: %v", err)), nil
	}

	// Update global config SelectedEnvironment
	gc, err := config.LoadGlobalConfig()
	if err == nil && gc != nil {
		gc.SelectedEnvironment = env
		_ = config.SaveGlobalConfig(gc)
	}

	return jsonResult(map[string]interface{}{
		"status":               "success",
		"previous_environment": oldEnv,
		"new_environment":      env,
		"project_id":           pc.ProjectID,
		"project_name":         pc.ProjectName,
	})
}

func (s *Server) handlePullSecrets(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	envParam, _ := args["environment"].(string)
	if envParam != "" {
		normalized, err := config.ParseEnvironment(envParam)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		envParam = normalized
	}

	pc, err := config.LoadProjectConfig()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to load project config: %v", err)), nil
	}

	activeEnv := pc.Environment
	didSwitch := false

	if envParam != "" && envParam != activeEnv {
		// Temporarily or permanently switch to pull
		pc.Environment = envParam
		if err := config.SaveProjectConfig(pc); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to update environment for pull: %v", err)), nil
		}
		didSwitch = true
		activeEnv = envParam

		// Update global config
		gc, err := config.LoadGlobalConfig()
		if err == nil && gc != nil {
			gc.SelectedEnvironment = envParam
			_ = config.SaveGlobalConfig(gc)
		}
	}

	svc := s.getSecretsService()
	if err := svc.Pull(nil); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("pull failed: %v", err)), nil
	}

	// Sync allowlist to local keyring (matches CLI pull behavior)
	if pc.WorkspaceID != "" {
		wsSvc := s.getWorkspaceService()
		if domainsResp, alErr := wsSvc.ListAllowlist(pc.WorkspaceID); alErr == nil {
			var domains []string
			for _, d := range domainsResp {
				domains = append(domains, d.Domain)
			}
			_ = keyring.SetWorkspaceAllowlist(pc.WorkspaceID, domains)
		}
	}

	msg := fmt.Sprintf("Successfully pulled secrets for environment: %s", activeEnv)
	if didSwitch {
		msg = fmt.Sprintf("Switched to environment %s and successfully pulled secrets.", activeEnv)
	}

	return jsonResult(map[string]interface{}{
		"status":      "success",
		"environment": activeEnv,
		"message":     msg,
	})
}

func (s *Server) handleRotateKey(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	keyName, _ := args["key_name"].(string)
	if keyName == "" {
		return mcp.NewToolResultError("missing required parameter: key_name"), nil
	}

	envParam, _ := args["environment"].(string)
	if envParam != "" {
		normalized, err := config.ParseEnvironment(envParam)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		envParam = normalized
	}

	pc, err := config.LoadProjectConfig()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to load project config: %v", err)), nil
	}

	activeEnv := pc.Environment
	didSwitch := false

	if envParam != "" && envParam != activeEnv {
		pc.Environment = envParam
		if err := config.SaveProjectConfig(pc); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to switch environment for key deletion: %v", err)), nil
		}
		didSwitch = true
		activeEnv = envParam

		// Update global config
		gc, err := config.LoadGlobalConfig()
		if err == nil && gc != nil {
			gc.SelectedEnvironment = envParam
			_ = config.SaveGlobalConfig(gc)
		}
	}

	svc := s.getSecretsService()
	if err := svc.Delete(keyName); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to delete key: %v", err)), nil
	}

	msg := fmt.Sprintf("Successfully deleted key %s from environment %s", keyName, activeEnv)
	if didSwitch {
		msg = fmt.Sprintf("Switched to environment %s and successfully deleted key %s", activeEnv, keyName)
	}

	return jsonResult(map[string]interface{}{
		"status":      "success",
		"key_name":    keyName,
		"environment": activeEnv,
		"message":     msg,
		"next_step":   "Store the new value without exposing it: use the secret_store tool (source generate | command | http), or run `agentsecrets secrets set KEY_NAME` from a terminal.",
	})
}

// handleSecretStore stores a secret from a source the agent names. The value
// never appears in the tool arguments or the result.
func (s *Server) handleSecretStore(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()

	keyName, _ := args["key_name"].(string)
	source, _ := args["source"].(string)
	environment, _ := args["environment"].(string)
	extract, _ := args["extract"].(string)

	if keyName == "" {
		return mcp.NewToolResultError("missing required parameter: key_name"), nil
	}
	if environment != "" {
		normalized, err := config.ParseEnvironment(environment)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		environment = normalized
	}

	if source == "" {
		return mcp.NewToolResultError("missing required parameter: source (generate | command | http)"), nil
	}

	svc := s.getSecretsService()

	var (
		meta secrets.StoredMeta
		err  error
	)
	switch source {
	case "generate":
		length := 32
		if n, ok := args["length"].(float64); ok && n > 0 {
			length = int(n)
		}
		meta, err = svc.Generate(keyName, length, environment)
	case "command":
		command, _ := args["command"].(string)
		if strings.TrimSpace(command) == "" {
			return mcp.NewToolResultError("source=command requires the command parameter"), nil
		}
		meta, err = svc.SetFromCommand(keyName, command, extract, environment)
	case "http":
		url, _ := args["url"].(string)
		if strings.TrimSpace(url) == "" {
			return mcp.NewToolResultError("source=http requires the url parameter"), nil
		}
		headers := map[string]string{}
		if hdrs, ok := args["headers"].(map[string]interface{}); ok {
			for k, v := range hdrs {
				if sv, ok := v.(string); ok {
					headers[k] = sv
				}
			}
		}
		meta, err = svc.SetFromHTTP(keyName, url, extract, environment, headers)
	default:
		return mcp.NewToolResultError(fmt.Sprintf("invalid source %q — must be generate, command, or http", source)), nil
	}

	if err != nil {
		// The error comes from validation, the source, or the store. It never
		// carries a secret value, so it is safe to surface.
		return mcp.NewToolResultError(fmt.Sprintf("secret_store failed: %v", err)), nil
	}

	return jsonResult(map[string]interface{}{
		"status":      "stored",
		"key_name":    meta.Key,
		"environment": meta.Environment,
		"length":      meta.Length,
		"fingerprint": meta.Fingerprint,
	})
}
