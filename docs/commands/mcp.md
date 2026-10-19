# agentsecrets mcp

> Model Context Protocol (MCP) server for Claude Desktop, Cursor, and AI IDEs.

## Usage

```bash
# Start MCP server over stdio
agentsecrets mcp serve

# Install MCP server configuration into Claude Desktop / Cursor
agentsecrets mcp install

# Output MCP server JSON configuration
agentsecrets mcp config
```

---

## Capabilities

* **`list_secrets`**: AI agent discovers available secret names for the active project (values are never returned).
* **`api_call`**: AI agent performs authenticated API requests by referencing secret names. The proxy resolves values in memory and injects them into outbound HTTP requests.

For configuration and IDE setup guides, visit:
👉 **[Zero-Knowledge MCP Server Guide](https://docs.agentsecrets.tech/ecosystem/zk-mcp)**
👉 **[Claude Desktop & Cursor Integration](https://docs.agentsecrets.tech/integrations/claude-desktop)**