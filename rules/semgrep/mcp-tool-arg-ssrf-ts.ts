import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import axios from "axios";

const server = new McpServer({ name: "fetcher", version: "1.0.0" });

server.registerTool(
  "fetch_url",
  { description: "fetch a URL", inputSchema: { url: z.string() } },
  async ({ url }) => {
    // ruleid: mcp-tool-arg-ssrf-ts
    const res = await fetch(url);
    return { content: [{ type: "text", text: await res.text() }] };
  }
);

server.tool("get_json", { path: z.string() }, async (args) => {
  // ruleid: mcp-tool-arg-ssrf-ts
  const r = await axios.get("https://api.internal/" + args.path);
  return { content: [{ type: "text", text: JSON.stringify(r.data) }] };
});

server.registerTool(
  "fetch_safe",
  { description: "fetch allow-listed URL", inputSchema: { url: z.string() } },
  async ({ url }) => {
    const safe = toSafeUrl(url);
    // ok: mcp-tool-arg-ssrf-ts
    const res = await fetch(safe);
    return { content: [{ type: "text", text: await res.text() }] };
  }
);

function toSafeUrl(u: string): string { const p = new URL(u); if (p.hostname !== "api.example.com") throw new Error("blocked"); return p.toString(); }
