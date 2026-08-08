import { expect, test } from "bun:test";
import { createDispatcher, getLoaderId, parseTargets } from "../src/cdp.ts";
import type { Send } from "../src/cdp.ts";

test("parseTargets finds a page by id", () => {
  const list = [{ id: "AAA", type: "page", url: "https://x.com", webSocketDebuggerUrl: "ws://a" }];
  expect(parseTargets(list, "AAA")).toEqual({ wsUrl: "ws://a", url: "https://x.com" });
});
test("parseTargets throws tab_unavailable when missing", () => {
  expect(() => parseTargets([], "AAA")).toThrow("tab_unavailable");
});

// ── M2: the per-command timeout must be CLEARED when the command settles ─────
//
// An uncleared 15s timer keeps its closure — and with it the `params` object,
// which for `Input.insertText` is the PLAINTEXT password — reachable long after
// the caller ran `secret = ""`. That turns a bounded round-trip into a 15-second
// plaintext residency for every keystroke the tool sends.

const SECRET = "hunter2-must-not-linger";

/**
 * Counts UNCLEARED timers by wrapping the globals. Must stay installed while the
 * dispatcher runs, so `restore` is explicit rather than scoped to a callback.
 */
function timerCounter() {
  const realSet = globalThis.setTimeout, realClear = globalThis.clearTimeout;
  const live = new Set<unknown>();
  (globalThis as any).setTimeout = (cb: any, ms: any, ...rest: any[]) => {
    const h = (realSet as any)(cb, ms, ...rest); live.add(h); return h;
  };
  (globalThis as any).clearTimeout = (h: any) => { live.delete(h); return (realClear as any)(h); };
  return {
    live: () => live.size,
    restore: () => {
      for (const h of live) (realClear as any)(h);
      globalThis.setTimeout = realSet; globalThis.clearTimeout = realClear;
    },
  };
}

test("M2: a resolved command leaves NO timer holding the typed plaintext", async () => {
  const frames: string[] = [];
  const t = timerCounter();
  try {
    const { send, handle } = createDispatcher((f) => frames.push(f), 15000);

    const p = send("Input.insertText", { text: SECRET });
    expect(frames.join("")).toContain(SECRET); // the command really did carry it
    expect(t.live()).toBe(1);                  // …and a timer really was armed

    handle(JSON.stringify({ id: 1, result: {} }));
    await p;

    expect(t.live()).toBe(0); // ← the timer, and its hold on the plaintext, is gone
  } finally { t.restore(); }
});

test("M2: an ERRORED command clears its timer too", async () => {
  const t = timerCounter();
  try {
    const { send, handle } = createDispatcher(() => {}, 15000);
    const p = send("Input.insertText", { text: SECRET });
    handle(JSON.stringify({ id: 1, error: { message: "boom" } }));
    await expect(p).rejects.toThrow("cdp_error");
    expect(t.live()).toBe(0);
  } finally { t.restore(); }
});

test("M2: the timeout still fires when the browser never answers", async () => {
  const { send } = createDispatcher(() => {}, 5);
  await expect(send("Runtime.evaluate", {})).rejects.toThrow("cdp_timeout");
});

test("M2: settled commands are dropped from the pending map", async () => {
  const d = createDispatcher(() => {}, 15000);
  const p = d.send("Runtime.evaluate", {});
  expect(d.pendingCount()).toBe(1);
  d.handle(JSON.stringify({ id: 1, result: { ok: true } }));
  await p;
  expect(d.pendingCount()).toBe(0);
  d.handle(JSON.stringify({ id: 1, result: {} })); // a duplicate reply is inert
  expect(d.pendingCount()).toBe(0);
});

// ── C1's token source: the main frame's loaderId, read browser-side ──────────

test("getLoaderId reads the main frame's loaderId from the Page domain", async () => {
  const calls: string[] = [];
  const send: Send = (async (method: string) => {
    calls.push(method);
    return { frameTree: { frame: { id: "F1", loaderId: "LDR-42", url: "https://x.com" } } };
  }) as Send;
  expect(await getLoaderId(send)).toBe("LDR-42");
  // Browser-side, not page-world JS: a page cannot forge what it never evaluates.
  expect(calls).toEqual(["Page.getFrameTree"]);
});

test("getLoaderId returns '' when the browser gives no answer, so callers fail closed", async () => {
  const send: Send = (async () => ({})) as Send;
  expect(await getLoaderId(send)).toBe("");
});
