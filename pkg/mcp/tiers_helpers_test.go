package mcp

// Test helpers. newTestServer builds a server with no external dependencies so
// tier registration can be asserted without a network or a keychain.

import (
	"testing"

	"github.com/mark3labs/mcp-go/server"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	srv := &Server{tiers: make(map[string]Tier)}
	s := server.NewMCPServer("AgentSecrets", "test", server.WithToolCapabilities(false))

	// Mirror the real registration set exactly. If this list drifts from
	// newServer, TestEveryRegisteredToolHasATier still passes but proves less,
	// so it is kept in the same order as server.go.
	srv.add(s, read(apiCallTool(), srv.handleAPICall))
	srv.add(s, read(listKeysTool(), srv.handleListKeys))
	srv.add(s, read(checkKeyTool(), srv.handleCheckKey))
	srv.add(s, read(getCoverageTool(), srv.handleGetCoverage))
	srv.add(s, read(getStatusTool(), srv.handleGetStatus))
	srv.add(s, read(getEnvironmentTool(), srv.handleGetEnvironment))
	srv.add(s, write(switchEnvironmentTool(), srv.handleSwitchEnvironment))
	srv.add(s, write(pullSecretsTool(), srv.handlePullSecrets))
	srv.add(s, read(diffSecretsTool(), srv.handleDiffSecrets))
	srv.add(s, read(diffEnvironmentsTool(), srv.handleDiffEnvironments))
	srv.add(s, read(getProxyLogsTool(), srv.handleGetProxyLogs))
	srv.add(s, read(getBlockedRequestsTool(), srv.handleGetBlockedRequests))
	srv.add(s, read(getRedactionEventsTool(), srv.handleGetRedactionEvents))
	srv.add(s, read(getAuditSummaryTool(), srv.handleGetAuditSummary))
	srv.add(s, read(getAgentIdentityTool(), srv.handleGetAgentIdentity))
	srv.add(s, read(listAgentTokensTool(), srv.handleListAgentTokens))
	srv.add(s, read(checkDomainTool(), srv.handleCheckDomain))
	srv.add(s, read(getAllowlistTool(), srv.handleGetAllowlist))
	srv.add(s, destructive(rotateKeyTool(), srv.handleRotateKey))
	// secret_store is intentionally absent; see newServer for why.

	return srv
}

func tierOf(t *testing.T, name string) Tier {
	t.Helper()
	srv := newTestServer(t)
	tier, ok := srv.tiers[name]
	if !ok {
		t.Fatalf("tool %q is not registered; the tier map has no entry for it", name)
	}
	return tier
}
