#!/usr/bin/env node
import * as http from "node:http";
import { Readable } from "node:stream";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { createBridgeServer } from "./server.js";

const PORT = parseInt(process.env["AGENTSECRETS_MCP_HTTP_PORT"] ?? "3001", 10);
const HOST = process.env["AGENTSECRETS_MCP_HTTP_HOST"] ?? "127.0.0.1";

function buildAllowedOrigins(): Set<string> | null {
  const raw = process.env["AGENTSECRETS_MCP_ALLOWED_ORIGINS"]?.trim();
  if (!raw) return null;
  return new Set(raw.split(",").map((o) => o.trim()).filter(Boolean));
}

const ALLOWED_ORIGINS = buildAllowedOrigins();
process.env["AGENTSECRETS_MCP_MODE"] = "cloud";

function originAllowed(req: http.IncomingMessage): boolean {
  if (!ALLOWED_ORIGINS) return true;
  const origin = req.headers["origin"];
  if (!origin) return true;
  return ALLOWED_ORIGINS.has(origin);
}

function sendError(res: http.ServerResponse, status: number, message: string): void {
  const body = JSON.stringify({ error: message });
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function nodeToWebRequest(req: http.IncomingMessage): Request {
  const host = req.headers["host"] ?? "localhost";
  const protocol = (req.socket as any).encrypted ? "https" : "http";
  const url = new URL(req.url ?? "/", `${protocol}://${host}`);

  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      for (const v of value) headers.append(key, v);
    } else {
      headers.set(key, value);
    }
  }

  const hasBody = req.method !== "GET" && req.method !== "HEAD";
  const init: RequestInit = {
    method: req.method ?? "GET",
    headers,
  };

  if (hasBody) {
    init.body = Readable.toWeb(req) as ReadableStream<Uint8Array>;
    // Node.js fetch requires duplex: 'half' for streaming request bodies
    (init as any).duplex = "half";
  }

  return new Request(url, init);
}

async function sendWebResponse(webRes: Response, res: http.ServerResponse): Promise<void> {
  const headers: Record<string, string | string[]> = {};
  webRes.headers.forEach((value, key) => {
    headers[key] = value;
  });

  res.writeHead(webRes.status, webRes.statusText, headers);

  if (webRes.body) {
    const reader = webRes.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(value);
      }
    } finally {
      reader.releaseLock();
      res.end();
    }
  } else {
    res.end();
  }
}

const handler = createMcpHandler(() => createBridgeServer());

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers["host"] ?? "localhost"}`);

  if (req.method === "GET" && url.pathname === "/health") {
    const body = JSON.stringify({ status: "ok", transport: "streamable-http" });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(body);
    return;
  }

  if (url.pathname !== "/mcp") {
    sendError(res, 404, "Not found. MCP endpoint is POST /mcp");
    return;
  }

  if (req.method !== "POST") {
    res.writeHead(405, { Allow: "POST" });
    res.end();
    return;
  }

  if (!originAllowed(req)) {
    sendError(res, 403, "Forbidden: Origin not allowed");
    return;
  }

  const authHeader = req.headers["authorization"];
  if (authHeader?.startsWith("Bearer ")) {
    const bearer = authHeader.slice(7).trim();
    if (bearer) process.env["AGENTSECRETS_TOKEN"] = bearer;
  }

  res.setHeader("X-Accel-Buffering", "no");

  try {
    const webReq = nodeToWebRequest(req);
    const webRes = await handler.fetch(webReq);
    await sendWebResponse(webRes, res);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[agentsecrets-mcp/http] handler error: ${msg}`);
    if (!res.headersSent) {
      sendError(res, 500, "Internal server error");
    }
  }
});

server.listen(PORT, HOST, () => {
  console.error(`[agentsecrets-mcp/http] Streamable HTTP MCP server listening on http://${HOST}:${PORT}/mcp`);
  console.error("[agentsecrets-mcp/http] Mode: Cloud only. Auth: Authorization: Bearer <token>");
});

server.on("error", (e) => {
  console.error(`[agentsecrets-mcp/http] Server error: ${e.message}`);
  process.exit(1);
});
