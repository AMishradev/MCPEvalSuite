import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import fs from "fs/promises";
import path from "path";

const server = new McpServer({ name: "files", version: "1.0.0" });
const ROOT = "/srv/data";

server.registerTool(
  "read_file",
  { description: "read a file", inputSchema: { name: z.string() } },
  async ({ name }) => {
    // ruleid: mcp-tool-arg-path-traversal-ts
    const data = await fs.readFile(path.join(ROOT, name), "utf8");
    return { content: [{ type: "text", text: data }] };
  }
);

server.tool("rm", { target: z.string() }, async (args) => {
  // ruleid: mcp-tool-arg-path-traversal-ts
  await fs.rm(args.target, { recursive: true });
  return { content: [] };
});

server.registerTool(
  "read_file_safe",
  { description: "read a file", inputSchema: { name: z.string() } },
  async ({ name }) => {
    const p = await validatePath(name);
    // ok: mcp-tool-arg-path-traversal-ts
    const data = await fs.readFile(p, "utf8");
    return { content: [{ type: "text", text: data }] };
  }
);

async function validatePath(requested: string): Promise<string> {
  const abs = path.resolve(ROOT, requested);
  if (!abs.startsWith(ROOT + path.sep)) throw new Error("outside root");
  return abs;
}
