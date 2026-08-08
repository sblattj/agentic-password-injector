#!/usr/bin/env bun
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { MANIFEST, TOOLS } from "./tools.ts";
// Single source of truth for the version: package.json. A hand-copied constant
// here (and the former stray `VERSION` file) drifted from it silently, and the
// version is what an MCP client reports back to the user.
import pkg from "../package.json" with { type: "json" };
const VERSION: string = pkg.version;
const server = new Server({ name: "agentic-password-injector", version: VERSION }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: MANIFEST }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const fn = TOOLS[req.params.name];
  if (!fn) throw new Error(`unknown tool: ${req.params.name}`);
  const out = await fn(req.params.arguments ?? {});
  return { content: [{ type: "text", text: JSON.stringify(out) }] };
});
await server.connect(new StdioServerTransport());
console.error(`[agentic-password-injector] v${VERSION} ready`);
