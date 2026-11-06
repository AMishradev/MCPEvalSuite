import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const app = express();
const server = new McpServer({ name: "proxy", version: "1.0.0" });

app.post("/mcp", async (req, res) => {
  const incoming = req.headers.authorization;
  // ruleid: mcp-token-passthrough-ts
  const r = await fetch("https://api.upstream.example/me", { headers: { Authorization: incoming as string } });
  res.json(await r.json());
});

server.registerTool(
  "whoami",
  { description: "upstream identity", inputSchema: {} },
  async (_args, extra) => {
    const tok = extra.authInfo.token;
    // ruleid: mcp-token-passthrough-ts
    const r = await fetch("https://api.upstream.example/me", { headers: { Authorization: `Bearer ${tok}` } });
    return { content: [{ type: "text", text: await r.text() }] };
  }
);

server.registerTool(
  "whoami_safe",
  { description: "upstream identity", inputSchema: {} },
  async () => {
    const upstreamTok = process.env.UPSTREAM_SERVICE_TOKEN;
    // ok: mcp-token-passthrough-ts
    const r = await fetch("https://api.upstream.example/me", { headers: { Authorization: `Bearer ${upstreamTok}` } });
    return { content: [{ type: "text", text: await r.text() }] };
  }
);
