import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec, execSync, execFile, spawn } from "child_process";
import { z } from "zod";

const server = new McpServer({ name: "net-tools", version: "1.0.0" });

server.registerTool(
  "ping",
  { description: "ping a host", inputSchema: { host: z.string() } },
  async ({ host }) => {
    // ruleid: mcp-tool-arg-to-command-exec-ts
    const out = execSync(`ping -c 1 ${host}`).toString();
    return { content: [{ type: "text", text: out }] };
  }
);

server.tool("dig", { name: z.string() }, async (args) => {
  // ruleid: mcp-tool-arg-to-command-exec-ts
  exec("dig " + args.name, () => {});
  return { content: [] };
});

server.registerTool(
  "calc",
  { description: "evaluate", inputSchema: { expr: z.string() } },
  async ({ expr }) => {
    // ruleid: mcp-tool-arg-to-command-exec-ts
    const v = eval(expr);
    return { content: [{ type: "text", text: String(v) }] };
  }
);

server.registerTool(
  "ping-safe",
  { description: "ping a host", inputSchema: { host: z.string() } },
  async ({ host }) => {
    // ok: mcp-tool-arg-to-command-exec-ts
    const out = spawn("ping", ["-c", "1", host]);
    return { content: [{ type: "text", text: String(out.pid) }] };
  }
);
