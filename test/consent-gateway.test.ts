// test/consent-gateway.test.ts
//
// Issue #1, end to end: the REAL server (`src/mcp.ts` over stdio, the way a
// gateway runs it) with a stand-in `osascript` and `security` on PATH and a fake
// CDP browser. Nothing here touches the real Keychain, a real browser, or puts a
// dialog on the screen.
//
// The failure case from the issue:
//   - the consent dialog waited 60 s, past a gateway's ~30 s call timeout;
//   - `execFileSync("osascript")` froze the event loop, so `tools/list` and
//     health checks went unanswered while the dialog was up;
//   - a late Allow after the caller had gone away still typed into the page.
import { afterAll, beforeAll, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ORIGIN = "https://forms.example.test";
const SECRET = "synthetic-secret-value";
const ROOT = join(import.meta.dir, "..");

let dir = "";
let cdp: ReturnType<typeof Bun.serve>;
const inserted: string[] = [];

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "apinj-issue1-"));
  // The dialog stand-in: records the AppleScript it was asked to show, waits
  // like a human would, then prints what the button press would print.
  writeFileSync(join(dir, "osascript"),
    `#!/bin/bash\nprintf '%s\\n' "$2" >> "$FAKE_OSA_LOG"\nsleep "\${FAKE_OSA_SLEEP:-0}"\nprintf '%s\\n' "$FAKE_OSA_OUT"\n`);
  // The Keychain stand-in: one named secret, bound to ORIGIN, selector allowed.
  writeFileSync(join(dir, "security"),
    `#!/bin/bash\ncase "$*" in\n  *" -w"*) printf '%s\\n' "${SECRET}" ;;\n` +
    `  *find-generic-password*) printf 'attributes:\\n    "acct"<blob>="agent"\\n    "icmt"<blob>="${ORIGIN} sel=allow kind=text"\\n' ;;\n` +
    `  *) exit 44 ;;\nesac\n`);
  chmodSync(join(dir, "osascript"), 0o755);
  chmodSync(join(dir, "security"), 0o755);

  // A one-tab browser whose page has one visible password field.
  cdp = Bun.serve({
    port: 0,
    fetch(req, srv) {
      const u = new URL(req.url);
      if (u.pathname === "/json/list") {
        return Response.json([{ id: "TAB1", type: "page", url: `${ORIGIN}/login`, webSocketDebuggerUrl: `ws://127.0.0.1:${srv.port}/devtools/page/TAB1` }]);
      }
      if (srv.upgrade(req, { data: undefined })) return;
      return new Response("no", { status: 404 });
    },
    websocket: {
      message(ws, raw) {
        const m = JSON.parse(String(raw));
        const reply = (result: unknown) => { ws.send(JSON.stringify({ id: m.id, result })); };
        if (m.method === "Page.getFrameTree") return reply({ frameTree: { frame: { loaderId: "LOADER-1" } } });
        if (m.method === "Input.insertText") { inserted.push(m.params.text); return reply({}); }
        if (m.method === "Runtime.evaluate") {
          if (m.params.expression === "document.location.origin") return reply({ result: { value: ORIGIN } });
          if (m.params.returnByValue === false) return reply({ result: { objectId: "OBJ1" } });
          return reply({ result: { value: { type: "password", visible: true } } });
        }
        if (m.method === "Runtime.callFunctionOn") return reply({ result: { value: true } });
        return reply({});
      },
    },
  });
});

afterAll(() => {
  cdp?.stop(true);
  if (dir) rmSync(dir, { recursive: true, force: true });
});

/** A stdio MCP client, as a gateway would be. Every frame is timestamped on arrival. */
function startServer(osa: { sleep: number; out: string }, extraEnv: Record<string, string> = {}) {
  const log = join(dir, `osa-${Math.random().toString(36).slice(2)}.log`);
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined) env[k] = v;
  delete env.CDP_ENDPOINTS;
  delete env.APINJ_CONSENT_TIMEOUT_S;
  Object.assign(env, {
    PATH: `${dir}:${process.env.PATH}`,
    HOME: dir, // no browser stores to find, no real profile read
    APINJ_CONFIRM: "1",
    CDP_BASE: `http://127.0.0.1:${cdp.port}`,
    FAKE_OSA_LOG: log,
    FAKE_OSA_SLEEP: String(osa.sleep),
    FAKE_OSA_OUT: osa.out,
    ...extraEnv,
  });
  const proc = Bun.spawn(["bun", "run", join(ROOT, "src/mcp.ts")], { cwd: ROOT, env, stdin: "pipe", stdout: "pipe", stderr: "pipe" });
  const frames: { at: number; msg: any }[] = [];
  const waiters: (() => void)[] = [];
  (async () => {
    let buf = "";
    const dec = new TextDecoder();
    for await (const chunk of proc.stdout) {
      buf += dec.decode(chunk);
      let i: number;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        frames.push({ at: performance.now(), msg: JSON.parse(line) });
        waiters.splice(0).forEach((w) => w());
      }
    }
  })();
  const send = (msg: object) => { proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", ...msg }) + "\n"); proc.stdin.flush(); };
  const response = (id: number, timeoutMs = 10_000) => new Promise<{ at: number; msg: any } | null>((ok) => {
    const t = setTimeout(() => ok(null), timeoutMs);
    const check = () => {
      const f = frames.find((x) => x.msg.id === id);
      if (f) { clearTimeout(t); ok(f); } else waiters.push(check);
    };
    check();
  });
  const init = async () => {
    send({ id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test-gateway", version: "0" } } });
    await response(1);
    send({ method: "notifications/initialized" });
  };
  const scripts = () => (existsSync(log) ? readFileSync(log, "utf8") : "");
  return { proc, send, response, init, scripts };
}

const fillSecret = (id: number) => ({ id, method: "tools/call", params: { name: "fill_secret", arguments: { tabId: "TAB1", name: "form-secret", selector: "#pw" } } });
const resultOf = (f: { msg: any } | null) => JSON.parse(f!.msg.result.content[0].text);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("control: a prompt Allow fills through the real server (the harness can pass)", async () => {
  inserted.length = 0;
  const s = startServer({ sleep: 0, out: "button returned:Allow, gave up:false" });
  try {
    await s.init();
    s.send(fillSecret(2));
    const r = await s.response(2);
    expect(resultOf(r)).toEqual({ filled: true });
    expect(inserted).toEqual([SECRET]);
  } finally { s.proc.kill(); }
}, 20_000);

test("issue #1: tools/list is answered while the consent dialog is open", async () => {
  const s = startServer({ sleep: 2, out: "button returned:Deny, gave up:false" });
  try {
    await s.init();
    s.send(fillSecret(2));
    await sleep(400); // the dialog is up now
    const asked = performance.now();
    s.send({ id: 3, method: "tools/list" });
    const list = await s.response(3);
    const call = await s.response(2);
    expect(list).not.toBeNull();
    // A frozen event loop answers only after the dialog closes (~1.6 s later).
    expect(list!.at - asked).toBeLessThan(800);
    expect(list!.at).toBeLessThan(call!.at);
    expect(resultOf(call)).toEqual({ filled: false, reason: "user_denied" });
  } finally { s.proc.kill(); }
}, 20_000);

test("issue #1: the dialog gives up below a 30 s gateway timeout, and says so", async () => {
  inserted.length = 0;
  // What osascript prints when `giving up after N` fires.
  const s = startServer({ sleep: 0, out: "button returned:, gave up:true" });
  try {
    await s.init();
    s.send(fillSecret(2));
    const r = await s.response(2);
    expect(s.scripts()).toContain("giving up after 25");
    expect(s.scripts()).not.toContain("giving up after 60");
    // A timeout is not a denial: the caller can tell "nobody answered" apart.
    expect(resultOf(r)).toEqual({ filled: false, reason: "consent_timeout" });
    expect(inserted).toEqual([]);
  } finally { s.proc.kill(); }
}, 20_000);

test("issue #1: APINJ_CONSENT_TIMEOUT_S sets the dialog timeout", async () => {
  const s = startServer({ sleep: 0, out: "button returned:Deny, gave up:false" }, { APINJ_CONSENT_TIMEOUT_S: "12" });
  try {
    await s.init();
    s.send(fillSecret(2));
    await s.response(2);
    expect(s.scripts()).toContain("giving up after 12");
  } finally { s.proc.kill(); }
}, 20_000);

test("issue #1: a late Allow after the caller cancelled types nothing", async () => {
  inserted.length = 0;
  // The human clicks Allow 1.5 s in; the caller gave up at 0.4 s.
  const s = startServer({ sleep: 1.5, out: "button returned:Allow, gave up:false" });
  try {
    await s.init();
    s.send(fillSecret(2));
    await sleep(400);
    s.send({ method: "notifications/cancelled", params: { requestId: 2, reason: "gateway timeout" } });
    await sleep(2500); // well past the late Allow
    expect(inserted).toEqual([]); // no silent fill the agent never hears about
    // The server is still healthy afterwards.
    s.send({ id: 3, method: "tools/list" });
    expect(await s.response(3, 3000)).not.toBeNull();
  } finally { s.proc.kill(); }
}, 20_000);
