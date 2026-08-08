import { expect, test } from "bun:test";
import { DETECT_EXPR, chooseFields, detectLoginFields, typeIntoField } from "../src/inject.ts";
import type { Send } from "../src/cdp.ts";

const SECRET = "hunter2-do-not-misfile";

test("chooseFields picks the password input and the preceding text input", () => {
  const inputs = [
    { sel: "#email", type: "email", visible: true, idx: 0 },
    { sel: "#pw", type: "password", visible: true, idx: 1 },
    { sel: "#hidden", type: "text", visible: false, idx: 2 },
  ];
  expect(chooseFields(inputs)).toEqual({ user: "#email", pass: "#pw" });
});
test("chooseFields returns pass-only when no user field precedes", () => {
  expect(chooseFields([{ sel: "#pw", type: "password", visible: true, idx: 0 }])).toEqual({ pass: "#pw" });
});

// ── I4: Input.insertText goes wherever FOCUS is, not to the resolved element ──
//
// `Input.insertText` is dispatched at the page. `.focus()` can fail silently
// (readonly/disabled/unfocusable) or be undone by an onfocus/focusin handler or
// an async steal between the two CDP round-trips — and the shipped code inserted
// anyway, returning {filled:true} while the password went into a different, quite
// possibly VISIBLE, input. These tests drive that steal.

interface Call { method: string; params: any }

/** A stub tab. `focusHolds` decides what the post-focus verification observes. */
function mkSend(opts: { objectId?: string | null; focusHolds: boolean | (() => boolean) }) {
  const calls: Call[] = [];
  const send: Send = (async (method: string, params: any = {}) => {
    calls.push({ method, params });
    if (method === "Runtime.evaluate") {
      return { result: { objectId: opts.objectId === undefined ? "OBJ-1" : opts.objectId } };
    }
    if (method === "Runtime.callFunctionOn") {
      const isCheck = String(params.functionDeclaration).includes("document.activeElement");
      if (!isCheck) return { result: { value: undefined } }; // the focus/scroll call
      const holds = typeof opts.focusHolds === "function" ? opts.focusHolds() : opts.focusHolds;
      return { result: { value: holds } };
    }
    return { result: {} };
  }) as Send;
  return { send, calls };
}

const inserted = (calls: Call[]) => calls.filter((c) => c.method === "Input.insertText");

test("I4: typeIntoField inserts when focus landed on the intended element", async () => {
  const { send, calls } = mkSend({ focusHolds: true });
  await typeIntoField(send, "#pw", SECRET);
  expect(inserted(calls).map((c) => c.params.text)).toEqual([SECRET]);
});

test("I4: a page that steals focus between focus and insert gets NOTHING typed", async () => {
  // The steal happens after the focus round-trip returns, which is exactly why
  // the verification is its own round-trip rather than bundled into the focus call.
  const { send, calls } = mkSend({ focusHolds: false });
  await expect(typeIntoField(send, "#pw", SECRET)).rejects.toThrow("focus_lost");
  expect(inserted(calls)).toEqual([]);
  expect(JSON.stringify(calls)).not.toContain(SECRET);
});

test("I4: the verification happens AFTER the focus call and BEFORE the insert", async () => {
  const { send, calls } = mkSend({ focusHolds: true });
  await typeIntoField(send, "#pw", SECRET);
  const order = calls.map((c) =>
    c.method === "Runtime.callFunctionOn"
      ? (String(c.params.functionDeclaration).includes("document.activeElement") ? "verify" : "focus")
      : c.method);
  expect(order).toEqual(["Runtime.evaluate", "focus", "verify", "Input.insertText"]);
});

test("I4: the focus check is boolean-only — it never reads the field's value", async () => {
  const { send, calls } = mkSend({ focusHolds: true });
  await typeIntoField(send, "#pw", SECRET);
  const check = calls.find((c) => String(c.params.functionDeclaration ?? "").includes("document.activeElement"))!;
  expect(String(check.params.functionDeclaration)).not.toContain(".value");
  expect(check.params.returnByValue).toBe(true);
});

test("I4: a readonly/disabled target is refused rather than typed past", async () => {
  // The real check is `this===document.activeElement && !this.readOnly && !this.disabled`,
  // so all three failures arrive here as the same false.
  const { send, calls } = mkSend({ focusHolds: false });
  await expect(typeIntoField(send, "#ro", SECRET)).rejects.toThrow("focus_lost");
  expect(inserted(calls)).toEqual([]);
});

test("I4: an unresolvable selector still fails before any insert", async () => {
  const { send, calls } = mkSend({ objectId: null, focusHolds: true });
  await expect(typeIntoField(send, "#gone", SECRET)).rejects.toThrow("tab_unavailable");
  expect(inserted(calls)).toEqual([]);
});

// ── M3: the guard→insert window ──────────────────────────────────────────────
//
// The caller re-asserts origin+loaderId immediately before calling this, but
// three CDP round-trips separate that assertion from the keystroke. The
// guard→resolveObjectId sub-window is the exploitable one: a document commit
// there yields a VALID objectId on the new document (the `[data-apinj="iN"]`
// stamp is deterministic and pre-placeable), focus lands, verify passes, and the
// password goes to the attacker. So the guard is re-asserted inside, last.

class Navigated extends Error { constructor() { super("navigated_during_consent"); } }

test("M3: a navigation after focus-verify but before insert types NOTHING", async () => {
  // The tab is fine right up to the verify; it moves in the instant before the
  // keystroke. Only a guard placed AFTER the verify can see this.
  const { send, calls } = mkSend({ focusHolds: true });
  let verified = false;
  const seenAt: string[] = [];
  const guard = async () => {
    seenAt.push(calls[calls.length - 1]?.method ?? "none");
    verified = calls.some((c) =>
      c.method === "Runtime.callFunctionOn" &&
      String(c.params.functionDeclaration).includes("document.activeElement"));
    if (verified) throw new Navigated();
  };
  await expect(typeIntoField(send, "#pw", SECRET, guard)).rejects.toThrow("navigated_during_consent");
  expect(inserted(calls)).toEqual([]);                 // ← the whole point
  expect(JSON.stringify(calls)).not.toContain(SECRET); // …and it is nowhere on the wire
  expect(verified).toBe(true);                         // the guard ran after the verify, not before it
});

test("M3: the guard is the LAST thing before Input.insertText", async () => {
  // Ordering is read from what the guard OBSERVES, not from a label: at the
  // moment it runs, resolve+focus+verify must already be on the wire and the
  // insert must not be.
  const { send, calls } = mkSend({ focusHolds: true });
  let atGuard: string[] = [];
  await typeIntoField(send, "#pw", SECRET, async () => { atGuard = calls.map((c) => c.method); });
  expect(atGuard).toEqual(["Runtime.evaluate", "Runtime.callFunctionOn", "Runtime.callFunctionOn"]);
  expect(atGuard).not.toContain("Input.insertText");
  expect(calls.map((c) => c.method)).toEqual([...atGuard, "Input.insertText"]);
});

test("M3: the guard is consulted exactly once, and a passing guard still fills", async () => {
  // Guards against the trivially-safe mutation (always abort) and the vacuous one
  // (never call it).
  const { send, calls } = mkSend({ focusHolds: true });
  let n = 0;
  await typeIntoField(send, "#pw", SECRET, async () => { n++; });
  expect(n).toBe(1);
  expect(inserted(calls).map((c) => c.params.text)).toEqual([SECRET]);
});

test("M3: focus_lost still wins over the guard — nothing typed, guard never needed", async () => {
  const { send, calls } = mkSend({ focusHolds: false });
  let n = 0;
  await expect(typeIntoField(send, "#pw", SECRET, async () => { n++; })).rejects.toThrow("focus_lost");
  expect(inserted(calls)).toEqual([]);
  expect(n).toBe(0);
});

test("M3: an omitted guard defaults to a no-op — non-gated callers still work", async () => {
  const { send, calls } = mkSend({ focusHolds: true });
  await typeIntoField(send, "#pw", SECRET);
  expect(inserted(calls).map((c) => c.params.text)).toEqual([SECRET]);
});

// ── I5: `offsetParent` is not a visibility test ──────────────────────────────
//
// A password input hidden with `opacity:0` earlier in DOM order has a truthy
// `offsetParent`, so the shipped `visible` flag called it visible and
// `vis.find(type==='password')` — first in DOM order — chose the DECOY. That is a
// credential-capture primitive for anyone with script on the matched origin. The
// expression is executed here against a minimal shim so the real serialized
// string is under test, not a re-implementation of it.

class El {
  attrs: Record<string, string> = {};
  constructor(public p: {
    type?: string; w?: number; h?: number;
    opacity?: string; visibility?: string; display?: string; offsetParent?: boolean;
  } = {}) {}
  get type() { return this.p.type ?? "text"; }
  get offsetParent() { return this.p.offsetParent === false ? null : {}; }
  getBoundingClientRect() { return { width: this.p.w ?? 120, height: this.p.h ?? 24 }; }
  setAttribute(k: string, v: string) { this.attrs[k] = v; }
  getAttribute(k: string) { return this.attrs[k] ?? null; }
}
class Doc {
  constructor(public els: El[]) {}
  querySelectorAll(sel: string) { if (sel === "input") return this.els; throw new Error(`unsupported ${sel}`); }
}
const style = (e: El) => ({
  visibility: e.p.visibility ?? "visible",
  display: e.p.display ?? "block",
  opacity: e.p.opacity ?? "1",
});
const runDetect = (expr: string, doc: Doc) =>
  new Function("document", "getComputedStyle", `return ${expr}`)(doc, style);

/** The shipped-before-fix expression, kept verbatim as a regression witness. */
const OLD_DETECT_EXPR =
  `(()=>{const els=[...document.querySelectorAll('input')];return els.map((e,idx)=>{e.setAttribute('data-apinj','i'+idx);` +
  `return {sel:'[data-apinj="i'+idx+'"]',type:(e.type||'text'),visible:!!(e.offsetParent),idx};});})()`;

const decoyPage = () => new Doc([
  new El({ type: "password", opacity: "0" }),   // the capture decoy, first in DOM order
  new El({ type: "email" }),
  new El({ type: "password" }),                 // the real one
]);

test("I5: an opacity:0 decoy password input is NOT chosen — the real field is", () => {
  const infos = runDetect(DETECT_EXPR, decoyPage());
  expect(infos.map((i: any) => i.visible)).toEqual([false, true, true]);
  expect(chooseFields(infos)).toEqual({ user: '[data-apinj="i1"]', pass: '[data-apinj="i2"]' });
});

/** The shipped-before-fix chooser: first visible password in DOM order, no refusal. */
const OLD_CHOOSE = (inputs: any[]) => inputs.filter((i) => i.visible).find((i) => i.type === "password");

test("I5: the OLD offsetParent test DID pick the decoy — the test above is not vacuous", () => {
  const infos = runDetect(OLD_DETECT_EXPR, decoyPage());
  expect(infos.map((i: any) => i.visible)).toEqual([true, true, true]); // opacity:0 called "visible"
  expect(OLD_CHOOSE(infos).sel).toBe('[data-apinj="i0"]');              // ← the decoy wins
  // And the hardened chooser refuses even if fed the old flags, rather than
  // silently picking one of two "visible" password boxes.
  expect(chooseFields(infos)).toEqual({ ambiguous: true });
});

test("I5: every flavour of visually-hidden password input is excluded", () => {
  for (const hidden of [
    { opacity: "0" }, { opacity: "0.0" }, { visibility: "hidden" }, { visibility: "collapse" },
    { display: "none" }, { w: 0 }, { h: 0 }, { w: 0, h: 0 },
  ]) {
    const doc = new Doc([new El({ type: "password", ...hidden }), new El({ type: "password" })]);
    const infos = runDetect(DETECT_EXPR, doc);
    expect(infos[0].visible).toBe(false);
    expect(chooseFields(infos)).toEqual({ pass: '[data-apinj="i1"]' });
  }
});

test("I5: a genuinely visible field is still visible (the test can fail both ways)", () => {
  const infos = runDetect(DETECT_EXPR, new Doc([new El({ type: "password" })]));
  expect(infos[0].visible).toBe(true);
  expect(chooseFields(infos)).toEqual({ pass: '[data-apinj="i0"]' });
});

test("I5: TWO genuinely visible password inputs REFUSE rather than guessing", () => {
  const doc = new Doc([new El({ type: "text" }), new El({ type: "password" }), new El({ type: "password" })]);
  const infos = runDetect(DETECT_EXPR, doc);
  const chosen = chooseFields(infos);
  expect(chosen).toEqual({ ambiguous: true });
  expect(chosen.pass).toBeUndefined(); // nothing to type into = nothing typed
});

test("I5: detectLoginFields wires the hardened expression through, not a copy", async () => {
  const doc = decoyPage();
  const send: Send = (async (method: string, params: any) => {
    expect(method).toBe("Runtime.evaluate");
    return { result: { value: runDetect(params.expression, doc) } };
  }) as Send;
  expect(await detectLoginFields(send)).toEqual({ user: '[data-apinj="i1"]', pass: '[data-apinj="i2"]' });
});
