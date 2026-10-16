#!/usr/bin/env node
/**
 * agentsecrets-mcp — AgentSecrets MCP bridge (stdio).
 *
 * One install serves all projects: identity resolves from OAuth session /
 * token files / local CLI, project context resolves per call (explicit
 * params → path → env hints → cwd project.json → pinned defaults).
 * Secret values and token values NEVER appear in tool input or output.
 */

import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { createBridgeServer } from './server.js';

serveStdio(() => createBridgeServer());
