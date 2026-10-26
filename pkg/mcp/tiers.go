package mcp

// Permission tiers for model-facing surfaces.
//
// An agent is an untrusted control path. A poisoned web page, issue, or tool
// result can instruct it to delete a credential, widen an allowlist, or mint a
// token, and it will comply unless the product refuses. Value-blindness does
// not help here: deleting a credential that is in use is damaging without ever
// seeing its value.
//
// So every tool on this surface declares a tier, and the tier is enforced at
// registration rather than inside each handler. A handler cannot forget to
// check, because it cannot be registered without a tier.
//
//   - TierRead     always available. No state change an injected instruction
//                  benefits from: list, diff, status, audit, tamper checks.
//   - TierWrite    refused unless a human enabled writes at server start.
//                  Create, update, pull, push, switch. Reversible, but still a
//                  mutation the model should not reach on its own.
//   - TierDestructive  refused unless a human enabled writes at server start,
//                  and requires an explicit confirm argument. Delete, revoke.
//
// The enable switch is an environment variable set by the human who configured
// the MCP client, not by the model: a model cannot set its own process
// environment. That is the whole boundary.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Tier classifies what a tool may do.
type Tier string

const (
	TierRead        Tier = "read"
	TierWrite       Tier = "write"
	TierDestructive Tier = "destructive"
)

// EnvAllowWrites is the human-controlled switch. It must be set in the MCP
// client configuration by the person who installed it. A model cannot set its
// own environment, so this cannot be flipped by an injected instruction.
const EnvAllowWrites = "AGENTSECRETS_MCP_ALLOW_WRITES"

// AllowWrites reports whether a human enabled mutating tools for this process.
// Only the exact value "true" enables them; a typo fails closed.
func AllowWrites() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(EnvAllowWrites)), "true")
}

// tieredTool pairs a tool with its tier so registration is the enforcement
// point.
type tieredTool struct {
	tool    mcp.Tool
	tier    Tier
	handler server.ToolHandlerFunc
}

// read, write and destructive are the three constructors used at the call site.
// They exist so the tier is visible on the same line as the tool, which makes a
// missing tier a compile error rather than a silent gap.
func read(tool mcp.Tool, h server.ToolHandlerFunc) tieredTool {
	return tieredTool{tool: tool, tier: TierRead, handler: h}
}

func write(tool mcp.Tool, h server.ToolHandlerFunc) tieredTool {
	return tieredTool{tool: tool, tier: TierWrite, handler: h}
}

func destructive(tool mcp.Tool, h server.ToolHandlerFunc) tieredTool {
	return tieredTool{tool: tool, tier: TierDestructive, handler: h}
}

// gate refuses a tool call whose tier is not permitted right now.
//
// The refusal is written for the model that receives it, not for a log. It
// names the tier, says who can enable it, and gives the human command to run,
// because the useful behavior is for the agent to hand the task back rather
// than retry or invent a workaround.
func gate(tier Tier, toolName string) error {
	if tier == TierRead {
		return nil
	}
	if AllowWrites() {
		return nil
	}
	human := fmt.Sprintf("agentsecrets %s", humanCommand(toolName))
	return fmt.Errorf(
		"refused: %q is a %s tool and writes are disabled for agent surfaces. "+
			"This is a deliberate guard against prompt injection, not a missing feature. "+
			"Tell the user what you wanted to do and give them this command to run themselves: %s. "+
			"If the user genuinely wants agents to write, they can set %s=true in the MCP client configuration and restart the server. "+
			"You cannot enable it yourself, and you should not ask the user to paste a secret value into chat.",
		toolName, tier, human, EnvAllowWrites,
	)
}

// humanCommand maps a tool name to the CLI equivalent a human should run.
func humanCommand(tool string) string {
	switch tool {
	case "switch_environment":
		return "environment switch <name>"
	case "pull_secrets":
		return "secrets pull"
	case "rotate_key":
		return "secrets delete <KEY>"
	case "secret_store":
		return "secrets set <KEY> --generate"
	default:
		return "<the equivalent command>"
	}
}

// add registers a tool behind its tier.
func (s *Server) add(srv *server.MCPServer, t tieredTool) {
	name := t.tool.Name
	inner := t.handler
	srv.AddTool(t.tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if err := gate(t.tier, name); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return inner(ctx, req)
	})
	s.tiers[name] = t.tier
}

// TierReport describes the current permission state. It is returned by the
// status tool so an agent, and the human reading the transcript, can see which
// tier each tool is in instead of assuming.
func (s *Server) TierReport() map[string]interface{} {
	byTier := map[Tier][]string{}
	for name, tier := range s.tiers {
		byTier[tier] = append(byTier[tier], name)
	}
	for _, names := range byTier {
		sort.Strings(names)
	}
	return map[string]interface{}{
		"writes_enabled": AllowWrites(),
		"enabled_by":     EnvAllowWrites,
		"read":           byTier[TierRead],
		"write":          byTier[TierWrite],
		"destructive":    byTier[TierDestructive],
		"note": "Write and destructive tools are refused unless a human set " +
			EnvAllowWrites + "=true in the MCP client configuration. " +
			"An agent cannot enable them.",
	}
}
