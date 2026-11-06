import express from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { randomUUID } from "node:crypto";

const app = express();

// ruleid: mcp-http-transport-without-dns-rebinding-protection-ts
const t1 = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });

// ok: mcp-http-transport-without-dns-rebinding-protection-ts
const t2 = new StreamableHTTPServerTransport({
  sessionIdGenerator: () => randomUUID(),
  enableDnsRebindingProtection: true,
  allowedHosts: ["127.0.0.1", "localhost"],
});

// ruleid: mcp-http-transport-without-dns-rebinding-protection-ts
app.listen(3000, "0.0.0.0", () => {});

// ok: mcp-http-transport-without-dns-rebinding-protection-ts
app.listen(3000, "127.0.0.1", () => {});
