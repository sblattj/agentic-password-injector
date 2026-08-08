// test/mcp.test.ts
//
// The registration seam. `MANIFEST` is what a model is TOLD it can call and
// `TOOLS` is what actually runs, so a name that exists in one and not the other
// is either a tool nobody can reach or an advertised tool that throws
// `unknown tool`. Neither shows up in any other test — every other suite calls
// the handler functions directly, bypassing registration entirely.
//
// The old test here asserted `Array.isArray(MANIFEST)`, which passes on an empty
// manifest, i.e. on total registration failure.
import { expect, test } from "bun:test";
import { MANIFEST, TOOLS, fillCredential, fillTotp, listCredentials, login } from "../src/tools.ts";

const EXPECTED = ["list_credentials", "fill_credential", "login", "fill_totp"];

/**
 * What each tool's HANDLER actually reads out of `args`, transcribed from the
 * handler bodies. The manifest is asserted against this rather than against
 * itself, so a schema that drifts from its handler — a property the handler no
 * longer reads, or an argument the handler needs that is never declared — fails.
 */
const CONTRACT: Record<string, { required: string[]; optional: string[] }> = {
  // listCredentials reads: domain, name
  list_credentials: { required: ["domain"], optional: ["name"] },
  // fillCredential reads: field + gated(tabId, domain, name)
  fill_credential: { required: ["tabId", "domain", "field"], optional: ["name"] },
  // login reads: submit + gated(tabId, domain, name)
  login: { required: ["tabId", "domain"], optional: ["name", "submit"] },
  // fillTotp reads: selector, domain, name + gated(tabId, domain, name)
  fill_totp: { required: ["tabId", "domain"], optional: ["name", "selector"] },
};

test("MANIFEST names, TOOLS keys and the four shipped tools are the SAME set", () => {
  const manifestNames = MANIFEST.map((t) => t.name);
  // No duplicates: a second `register("login", …)` would silently shadow the
  // handler in TOOLS while leaving two entries in the manifest.
  expect(new Set(manifestNames).size).toBe(manifestNames.length);
  expect(manifestNames.sort()).toEqual([...EXPECTED].sort());
  expect(Object.keys(TOOLS).sort()).toEqual([...EXPECTED].sort());
});

test("every manifest entry resolves to a callable handler", () => {
  for (const t of MANIFEST) {
    expect(typeof TOOLS[t.name]).toBe("function");
    expect(t.description.length).toBeGreaterThan(20);
  }
});

test("each inputSchema declares exactly what its handler reads — no more, no less", () => {
  for (const t of MANIFEST) {
    const c = CONTRACT[t.name];
    expect(c).toBeDefined();
    const schema = t.inputSchema as {
      type: string; properties: Record<string, { type: string }>;
      required?: string[]; additionalProperties?: boolean;
    };
    expect(schema.type).toBe("object");
    // An open schema lets a caller smuggle properties past the declared surface.
    expect(schema.additionalProperties).toBe(false);
    expect(Object.keys(schema.properties).sort()).toEqual([...c.required, ...c.optional].sort());
    expect([...(schema.required ?? [])].sort()).toEqual([...c.required].sort());
    // Every declared property is described, because the description is the only
    // thing a calling model reads before choosing a value.
    for (const [k, v] of Object.entries(schema.properties)) {
      expect(typeof v.type).toBe("string");
      expect((v as { description?: string }).description ?? "").not.toBe("");
      expect(k).not.toBe("password");
    }
  }
});

test("the registered handler is the exported implementation, not a stub", async () => {
  // Probed through TOOLS (the registration path), with arguments that are refused
  // before any vault, browser or dialog is touched. A stub would not produce the
  // implementation's exact reason vocabulary.
  expect(await TOOLS.list_credentials({})).toEqual(await listCredentials({}));
  expect(await TOOLS.list_credentials({})).toEqual({ credentials: [], reason: "domain_required" });
  expect(await TOOLS.list_credentials({ domain: "com" })).toEqual({ credentials: [], reason: "bad_domain" });
  expect(await TOOLS.fill_credential({ domain: "x.com", tabId: "T" })).toEqual(await fillCredential({ domain: "x.com", tabId: "T" }));
  expect(await TOOLS.fill_credential({ domain: "x.com", tabId: "T" })).toEqual({ filled: false, reason: "bad_field" });
  expect(await TOOLS.login({ domain: "x.com" })).toEqual(await login({ domain: "x.com" }));
  expect(await TOOLS.login({ domain: "x.com" })).toEqual({ filled: false, reason: "tab_unavailable" });
  expect(await TOOLS.fill_totp({ tabId: "T" })).toEqual(await fillTotp({ tabId: "T" }));
  expect(await TOOLS.fill_totp({ tabId: "T" })).toEqual({ filled: false, reason: "domain_required" });
});

// ── The live server ──────────────────────────────────────────────────────────
// The assertions above are about the DATA in tools.ts. This one proves src/mcp.ts
// actually wires that data into the SDK: a broken `setRequestHandler` call, a bad
// import, or a server that dies on boot is invisible to every in-process test.

interface RpcMsg { id?: number; result?: any; error?: { message: string } }

async function rpc(requests: object[]): Promise<RpcMsg[]> {
  const proc = Bun.spawn([process.execPath, "run", `${import.meta.dir}/../src/mcp.ts`], {
    stdin: "pipe", stdout: "pipe", stderr: "pipe",
  });
  const w = proc.stdin as WritableStreamDefaultWriter | any;
  for (const r of requests) w.write(new TextEncoder().encode(JSON.stringify(r) + "\n"));
  await w.flush?.();

  const out: RpcMsg[] = [];
  const wanted = requests.filter((r) => "id" in r).length;
  const decoder = new TextDecoder();
  let buf = "";
  const deadline = Date.now() + 15_000;
  const reader = (proc.stdout as ReadableStream<Uint8Array>).getReader();
  while (out.length < wanted && Date.now() < deadline) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const lines = buf.split("\n");
    buf = lines.pop() ?? "";
    for (const l of lines) if (l.trim()) out.push(JSON.parse(l));
  }
  reader.cancel().catch(() => {});
  proc.kill();
  await proc.exited;
  return out;
}

const INIT = {
  jsonrpc: "2.0", id: 1, method: "initialize",
  params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "apinj-test", version: "0" } },
};
const INITED = { jsonrpc: "2.0", method: "notifications/initialized" };

test("src/mcp.ts serves the four tools over a real stdio session", async () => {
  const msgs = await rpc([INIT, INITED, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }]);
  const init = msgs.find((m) => m.id === 1);
  expect(init?.result?.serverInfo?.name).toBe("agentic-password-injector");
  // The version is single-sourced from package.json; an unresolved import would
  // surface here as undefined rather than as a passing test.
  expect(init?.result?.serverInfo?.version).toBe(
    (await Bun.file(`${import.meta.dir}/../package.json`).json()).version,
  );
  const list = msgs.find((m) => m.id === 2);
  expect((list?.result?.tools ?? []).map((t: { name: string }) => t.name).sort()).toEqual([...EXPECTED].sort());
}, 20_000);

test("a registered tool is genuinely callable over the wire, and an unknown one errors", async () => {
  const msgs = await rpc([
    INIT, INITED,
    // Refused at the entry point: no vault read, no browser, no dialog.
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "list_credentials", arguments: { domain: "com" } } },
    { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "no_such_tool", arguments: {} } },
  ]);
  const call = msgs.find((m) => m.id === 2);
  expect(JSON.parse(call?.result?.content?.[0]?.text ?? "{}")).toEqual({ credentials: [], reason: "bad_domain" });
  const bad = msgs.find((m) => m.id === 3);
  expect(bad?.error?.message ?? "").toContain("unknown tool");
}, 20_000);
