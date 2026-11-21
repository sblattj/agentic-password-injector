import { afterEach, beforeEach, expect, test } from "bun:test";
import { EndpointError, loadEndpoints, resolveTabRef, tabRefReason } from "../src/endpoints.ts";
import { resolveTarget, type Send } from "../src/cdp.ts";
import { login, fillSecret, type Deps } from "../src/tools.ts";
import { passkeyLogin, passkeyRegister, type PasskeyDeps } from "../src/passkeys.ts";

// ── Named CDP endpoints (issue #4) ───────────────────────────────────────────
//
// One server, several browsers. Config mirrors cdp-toolkit: CDP_BASE is the
// endpoint `default`; CDP_ENDPOINTS adds `name=url` pairs; `?mode=read` marks an
// endpoint the injector must never type into.

const LIVE = "teams=http://127.0.0.1:9333?mode=read,helium=http://127.0.0.1:9555";
const KEYS = ["CDP_BASE", "CDP_ENDPOINTS"] as const;
let saved: Record<string, string | undefined> = {};
beforeEach(() => { saved = Object.fromEntries(KEYS.map((k) => [k, process.env[k]])); for (const k of KEYS) delete process.env[k]; });
afterEach(() => { for (const k of KEYS) saved[k] === undefined ? delete process.env[k] : (process.env[k] = saved[k]); });

const codeOf = (fn: () => unknown) => { try { fn(); return null; } catch (e) { return (e as EndpointError).code; } };

// ── config parsing ───────────────────────────────────────────────────────────

test("parses the live cdp-toolkit string: read-only teams, writable helium, default 9222", () => {
  const c = loadEndpoints({ CDP_ENDPOINTS: LIVE });
  expect(c.get("default")).toEqual({ name: "default", base: "http://127.0.0.1:9222", readOnly: false });
  expect(c.get("teams")).toEqual({ name: "teams", base: "http://127.0.0.1:9333", readOnly: true });
  expect(c.get("helium")).toEqual({ name: "helium", base: "http://127.0.0.1:9555", readOnly: false });
});

test("CDP_BASE is the default endpoint, verbatim", () => {
  expect(loadEndpoints({ CDP_BASE: "http://127.0.0.1:9223" }).get("default")!.base).toBe("http://127.0.0.1:9223");
});

test("?mode=write is accepted and means writable", () => {
  expect(loadEndpoints({ CDP_ENDPOINTS: "b=http://127.0.0.1:1?mode=write" }).get("b")!.readOnly).toBe(false);
});

for (const [label, spec] of [
  ["a dash in the name", "my-br=http://127.0.0.1:1"],
  ["a duplicate name", "a=http://127.0.0.1:1,a=http://127.0.0.1:2"],
  ["no '='", "http://127.0.0.1:1"],
  ["a non-http scheme", "a=ws://127.0.0.1:1"],
  ["an unknown query key", "a=http://127.0.0.1:1?foo=1"],
  ["an unknown mode", "a=http://127.0.0.1:1?mode=rw"],
  ["a fragment", "a=http://127.0.0.1:1#x"],
  ["a bad URL", "a=not a url"],
] as const) {
  test(`malformed CDP_ENDPOINTS (${label}) is endpoint_config_error`, () => {
    expect(codeOf(() => loadEndpoints({ CDP_ENDPOINTS: spec }))).toBe("endpoint_config_error");
  });
}

test("CDP_BASE and a configured `default` that disagree are a config error", () => {
  expect(codeOf(() => loadEndpoints({ CDP_BASE: "http://127.0.0.1:1", CDP_ENDPOINTS: "default=http://127.0.0.1:2" })))
    .toBe("endpoint_config_error");
});

// ── tab references ───────────────────────────────────────────────────────────

test("a bare id is the default endpoint, never another one", () => {
  const r = resolveTabRef("AAA", { CDP_ENDPOINTS: LIVE });
  expect(r.endpoint.name).toBe("default");
  expect(r.targetId).toBe("AAA");
});

test("endpoint:<name>/<id> picks that endpoint", () => {
  const r = resolveTabRef("endpoint:helium/BBB", { CDP_ENDPOINTS: LIVE });
  expect(r.endpoint.base).toBe("http://127.0.0.1:9555");
  expect(r.targetId).toBe("BBB");
});

test("an unknown endpoint name is unknown_endpoint, not tab_unavailable", () => {
  expect(codeOf(() => resolveTabRef("endpoint:nope/BBB", { CDP_ENDPOINTS: LIVE }))).toBe("unknown_endpoint");
  expect(codeOf(() => resolveTabRef("endpoint:helium/BBB", {}))).toBe("unknown_endpoint");
});

test("a read-only endpoint refuses: endpoint_read_only", () => {
  expect(codeOf(() => resolveTabRef("endpoint:teams/BBB", { CDP_ENDPOINTS: LIVE }))).toBe("endpoint_read_only");
});

test("a read-only DEFAULT endpoint refuses bare ids too", () => {
  expect(codeOf(() => resolveTabRef("AAA", { CDP_ENDPOINTS: "default=http://127.0.0.1:9222?mode=read" }))).toBe("endpoint_read_only");
});

test("endpoint with no target id is refused: the tab is always explicit", () => {
  expect(codeOf(() => resolveTabRef("endpoint:helium", { CDP_ENDPOINTS: LIVE }))).toBe("tab_unavailable");
  expect(codeOf(() => resolveTabRef("endpoint:helium/", { CDP_ENDPOINTS: LIVE }))).toBe("tab_unavailable");
  expect(codeOf(() => resolveTabRef("endpoint:/BBB", { CDP_ENDPOINTS: LIVE }))).toBe("unknown_endpoint");
});

test("tabRefReason maps every refusal to a fixed code, and null for a usable ref", () => {
  const env = { CDP_ENDPOINTS: LIVE };
  expect(tabRefReason("", env)).toBe("tab_unavailable");
  expect(tabRefReason("AAA", env)).toBeNull();
  expect(tabRefReason("endpoint:helium/AAA", env)).toBeNull();
  expect(tabRefReason("endpoint:teams/AAA", env)).toBe("endpoint_read_only");
  expect(tabRefReason("endpoint:x/AAA", env)).toBe("unknown_endpoint");
  expect(tabRefReason("AAA", { CDP_ENDPOINTS: "bad" })).toBe("endpoint_config_error");
});

// ── the REAL resolveTarget against two fake DevTools servers ────────────────

function fakeDevtools(ids: string[]) {
  const server: ReturnType<typeof Bun.serve> = Bun.serve({
    port: 0,
    fetch(req): Response {
      const u = new URL(req.url);
      if (u.pathname !== "/json/list") return new Response("nope", { status: 404 });
      return Response.json(ids.map((id) => ({
        id, type: "page", url: `https://page-${id}.test/`,
        webSocketDebuggerUrl: `ws://127.0.0.1:${server.port}/devtools/page/${id}`,
      })));
    },
  });
  return server;
}

test("resolveTarget: a tab on endpoint B is missing by bare id and found with endpoint:B/", async () => {
  const a = fakeDevtools(["ONA"]);
  const b = fakeDevtools(["ONB"]);
  try {
    process.env.CDP_BASE = `http://127.0.0.1:${a.port}`;
    process.env.CDP_ENDPOINTS = `bee=http://127.0.0.1:${b.port}`;
    await expect(resolveTarget("ONB")).rejects.toThrow("tab_unavailable");
    expect((await resolveTarget("endpoint:bee/ONB")).wsUrl).toBe(`ws://127.0.0.1:${b.port}/devtools/page/ONB`);
    expect((await resolveTarget("ONA")).wsUrl).toBe(`ws://127.0.0.1:${a.port}/devtools/page/ONA`);
    await expect(resolveTarget("endpoint:bee/ONA")).rejects.toThrow("tab_unavailable");
  } finally { a.stop(true); b.stop(true); }
});

test("resolveTarget never touches the network for a read-only or unknown endpoint", async () => {
  let hits = 0;
  const ro = Bun.serve({ port: 0, fetch() { hits++; return Response.json([]); } });
  try {
    process.env.CDP_ENDPOINTS = `ro=http://127.0.0.1:${ro.port}?mode=read`;
    await expect(resolveTarget("endpoint:ro/X")).rejects.toThrow("endpoint_read_only");
    await expect(resolveTarget("endpoint:zz/X")).rejects.toThrow("unknown_endpoint");
    expect(hits).toBe(0);
  } finally { ro.stop(true); }
});

// ── the tools: gates apply per endpoint, refusals come before the vault ─────

const PASSWORD = "hunter2-endpoint-secret";

/**
 * Deps whose resolveTarget is the REAL one (two fake DevTools servers), and
 * whose socket layer answers per wsUrl, so each endpoint's tab has its own origin.
 */
function toolDeps(originByWs: Record<string, string>) {
  const spy = { vault: 0, consent: 0, typed: 0, wsUsed: [] as string[] };
  const d: Deps = {
    resolveCredential: async () => { spy.vault++; return { cred: { origin: "https://x.com", username: "u", getSecret: () => PASSWORD }, backend: "keychain" } as any; },
    resolveSecret: async () => { spy.vault++; return { origin: "https://x.com", flags: {}, getSecret: () => PASSWORD }; },
    resolveTarget,
    withConn: async (ws, fn) => {
      spy.wsUsed.push(ws);
      const origin = originByWs[ws] ?? "";
      const send: Send = (async (method: string) => {
        if (method === "Runtime.evaluate") return { result: { value: origin } };
        return { result: {} };
      }) as Send;
      return fn(send);
    },
    getOrigin: async (send) => ((await send<any>("Runtime.evaluate")).result.value as string),
    getLoaderId: async () => "LOADER-1",
    confirmInjection: async () => { spy.consent++; return true; },
    confirmSecret: async () => { spy.consent++; return true; },
    detectLoginFields: async () => ({ user: "#u", pass: "#p" }),
    typeIntoField: async () => { spy.typed++; },
    probeFields: async () => [],
    inspectField: async () => ({ type: "password", visible: true }),
    totpCode: () => "123456",
    keychainHasTotp: () => false,
    keychainTotpSeed: () => null,
  };
  return { d, spy };
}

test("origin gate is enforced on the second endpoint: evil tab there -> origin_mismatch, no consent, no keystroke", async () => {
  const a = fakeDevtools(["ONA"]);
  const b = fakeDevtools(["ONB"]);
  try {
    process.env.CDP_BASE = `http://127.0.0.1:${a.port}`;
    process.env.CDP_ENDPOINTS = `bee=http://127.0.0.1:${b.port}`;
    const wsB = `ws://127.0.0.1:${b.port}/devtools/page/ONB`;
    const wsA = `ws://127.0.0.1:${a.port}/devtools/page/ONA`;

    const evil = toolDeps({ [wsB]: "https://evil.test", [wsA]: "https://x.com" });
    expect(await login({ tabId: "endpoint:bee/ONB", domain: "x.com" }, evil.d)).toEqual({ filled: false, reason: "origin_mismatch" });
    expect(evil.spy.wsUsed).toEqual([wsB]);
    expect(evil.spy.consent).toBe(0);
    expect(evil.spy.typed).toBe(0);

    // Control: the same endpoint with a matching origin really does fill.
    const good = toolDeps({ [wsB]: "https://x.com" });
    const r = await login({ tabId: "endpoint:bee/ONB", domain: "x.com" }, good.d);
    expect(r.filled).toBe(true);
    expect(good.spy.wsUsed).toEqual([wsB]);
    expect(good.spy.consent).toBe(1);
    expect(good.spy.typed).toBe(2);

    // The bare id of a tab on bee does not resolve on the default endpoint.
    const bare = toolDeps({ [wsB]: "https://x.com" });
    expect(await login({ tabId: "ONB", domain: "x.com" }, bare.d)).toEqual({ filled: false, reason: "tab_unavailable" });
  } finally { a.stop(true); b.stop(true); }
});

test("read-only endpoint: every injecting tool refuses BEFORE the vault is read", async () => {
  process.env.CDP_ENDPOINTS = LIVE;
  const { d, spy } = toolDeps({});
  expect(await login({ tabId: "endpoint:teams/X", domain: "x.com" }, d)).toEqual({ filled: false, reason: "endpoint_read_only" });
  expect(await fillSecret({ tabId: "endpoint:teams/X", name: "s" }, d)).toEqual({ filled: false, reason: "endpoint_read_only" });
  expect(spy.vault).toBe(0);
  expect(spy.consent).toBe(0);
});

test("unknown endpoint: clear reason, vault untouched", async () => {
  process.env.CDP_ENDPOINTS = LIVE;
  const { d, spy } = toolDeps({});
  expect(await login({ tabId: "endpoint:nope/X", domain: "x.com" }, d)).toEqual({ filled: false, reason: "unknown_endpoint" });
  expect(spy.vault).toBe(0);
});

test("passkey tools refuse read-only and unknown endpoints before the passkey vault", async () => {
  process.env.CDP_ENDPOINTS = LIVE;
  let lookups = 0;
  const pd = {
    resolveTarget, withConn: async () => { throw new Error("no socket"); },
    getOrigin: async () => "", getLoaderId: async () => "",
    lookup: () => { lookups++; return null; }, store: () => {}, confirm: async () => true,
    sleep: async () => {}, now: () => 0,
  } as unknown as PasskeyDeps;
  expect(await passkeyLogin({ tabId: "endpoint:teams/X", name: "ex" }, pd)).toEqual({ used: false, reason: "endpoint_read_only" });
  expect(await passkeyRegister({ tabId: "endpoint:nope/X", name: "ex", origin: "https://x.com" }, pd)).toEqual({ saved: false, reason: "unknown_endpoint" });
  expect(lookups).toBe(0);
});
