#!/usr/bin/env bun
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { MANIFEST, TOOLS } from "./tools.ts";
import { runWithRequestSignal } from "./request.ts";
// Single source of truth for the version: package.json. A hand-copied constant
// here (and the former stray `VERSION` file) drifted from it silently, and the
// version is what an MCP client reports back to the user.
import pkg from "../package.json" with { type: "json" };
const VERSION: string = pkg.version;
const server = new Server({ name: "agentic-password-injector", version: VERSION }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: MANIFEST }));
server.setRequestHandler(CallToolRequestSchema, async (req, extra) => {
  const fn = TOOLS[req.params.name];
  if (!fn) throw new Error(`unknown tool: ${req.params.name}`);
  // The request's abort signal rides along in async context, so a cancelled or
  // disconnected call closes its dialog and types nothing (issue #1).
  const out = await runWithRequestSignal(extra.signal, () => fn(req.params.arguments ?? {}));
  return { content: [{ type: "text", text: JSON.stringify(out) }] };
});
await server.connect(new StdioServerTransport());
console.error(`[agentic-password-injector] v${VERSION} ready`);
