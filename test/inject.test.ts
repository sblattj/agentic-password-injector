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

// ── Shadow-DOM piercing ──────────────────────────────────────────────────────
//
// `document.querySelector` stops at a shadow boundary, so a field inside an open
// shadow root resolves to its HOST — a custom element such as <atlas-input>,
// Angular Material, Salesforce LWC. Focus lands on the host, and
// `Input.insertText` goes wherever focus really is. The expression under test is
// the shipped one, executed against a shim, not a re-implementation.

import { PIERCE_FN, inspectField } from "../src/inject.ts";

class SEl {
  shadowRoot: SRoot | null = null;
  constructor(public tag: string, public attrs: Record<string, string> = {}, public p: {
    type?: string; w?: number; h?: number; opacity?: string; visibility?: string; display?: string;
  } = {}) {}
  get type() { return this.p.type ?? "text"; }
  matches(sel: string) { return sel.split(",").includes(this.tag); }
  getBoundingClientRect() { return { width: this.p.w ?? 120, height: this.p.h ?? 24 }; }
  get offsetParent() { return {}; }
}
class SRoot {
  constructor(public els: SEl[]) {}
  all(): SEl[] { return this.els.flatMap((e) => [e, ...(e.shadowRoot ? e.shadowRoot.all() : [])]); }
  querySelectorAll(sel: string): SEl[] {
    if (sel === "*") return this.els;
    return this.els.filter((e) => matchSel(e, sel));
  }
  querySelector(sel: string): SEl | null { return this.querySelectorAll(sel)[0] ?? null; }
}
function matchSel(e: SEl, sel: string): boolean {
  if (sel.includes(",")) return sel.split(",").some((s) => matchSel(e, s.trim()));
  const attr = sel.match(/^\[([\w-]+)="([^"]+)"\]$/);
  if (attr) return e.attrs[attr[1]] === attr[2];
  const id = sel.match(/^#(.+)$/);
  if (id) return e.attrs.id === id[1];
  return e.tag === sel;
}
const sstyle = (e: SEl) => ({
  visibility: e.p.visibility ?? "visible",
  display: e.p.display ?? "block",
  opacity: e.p.opacity ?? "1",
});
const pierce = (sel: string, doc: SRoot) =>
  new Function("document", "sel", `return (${PIERCE_FN})(sel)`)(doc, sel);

test("PIERCE: a light-DOM hit is returned unchanged", () => {
  const input = new SEl("input", { id: "ssn" });
  expect(pierce("#ssn", new SRoot([input]))).toBe(input);
});

test("PIERCE: a hit ONE shadow root deep is found", () => {
  const inner = new SEl("input", { id: "ssn" });
  const host = new SEl("atlas-input");
  host.shadowRoot = new SRoot([inner]);
  expect(pierce("#ssn", new SRoot([host]))).toBe(inner);
});

test("PIERCE: a hit TWO shadow roots deep is found", () => {
  const inner = new SEl("input", { id: "ssn" });
  const mid = new SEl("atlas-field");
  mid.shadowRoot = new SRoot([inner]);
  const host = new SEl("atlas-input");
  host.shadowRoot = new SRoot([mid]);
  expect(pierce("#ssn", new SRoot([host]))).toBe(inner);
});

test("PIERCE: landing on a HOST descends to the input inside it", () => {
  // The realistic custom-element shape: the selector names the element, and the
  // field the human means is the <input> in its shadow root.
  const inner = new SEl("input");
  const host = new SEl("atlas-input", { id: "ssn" });
  host.shadowRoot = new SRoot([inner]);
  expect(pierce("#ssn", new SRoot([host]))).toBe(inner);
});

test("PIERCE: a genuine miss is null, not a nearby element", () => {
  const host = new SEl("atlas-input");
  host.shadowRoot = new SRoot([new SEl("input", { id: "dob" })]);
  expect(pierce("#ssn", new SRoot([host]))).toBe(null);
});

test("PIERCE: a CLOSED shadow root is not reachable — refusal, not a guess", () => {
  // shadowRoot is null for a closed root, so the walk simply never sees it.
  const host = new SEl("atlas-input");
  host.shadowRoot = null;
  expect(pierce("#ssn", new SRoot([host]))).toBe(null);
});

test("PIERCE: the resolver is INLINE — it installs nothing on the page", () => {
  // The reference script cached itself as `window.__pierce`, guarded by
  // `if (window.__pierce) return true`. A script on the matched origin that
  // pre-defines that global then chooses the target of every later injection.
  expect(PIERCE_FN).not.toContain("window.");
  expect(PIERCE_FN).not.toContain("__pierce");
  expect(PIERCE_FN.trimStart().startsWith("((sel)")).toBe(true);
});

test("PIERCE: typeIntoField resolves through the piercing expression, not querySelector alone", () => {
  const { send, calls } = mkSend({ focusHolds: true });
  return typeIntoField(send, "#ssn", SECRET).then(() => {
    const resolve = calls.find((c) => c.method === "Runtime.evaluate")!;
    expect(String(resolve.params.expression)).toContain("shadowRoot");
    expect(String(resolve.params.expression)).toContain('"#ssn"');
  });
});

// ── Deep activeElement (gotcha 3) ────────────────────────────────────────────

test("FOCUS: the check walks INTO shadow roots before comparing identity", () => {
  const { send, calls } = mkSend({ focusHolds: true });
  return typeIntoField(send, "#ssn", SECRET).then(() => {
    const check = calls.find((c) =>
      String(c.params.functionDeclaration ?? "").includes("document.activeElement"))!;
    const fn = String(check.params.functionDeclaration);
    // Without this walk, document.activeElement is the HOST and the identity
    // check is false for every field piercing actually reached — piercing and
    // focus-verification would be mutually exclusive.
    expect(fn).toContain("shadowRoot.activeElement");
    expect(fn).toContain("===this");
    // Still boolean-only: not a reveal path.
    expect(fn).not.toContain(".value");
  });
});

// ── The field is emptied before the insert ───────────────────────────────────

test("CLEAR: the focus round-trip also empties the field, in ONE call", async () => {
  // Input.insertText inserts at the caret rather than replacing, so a box that
  // already holds text gets the secret concatenated onto it.
  const { send, calls } = mkSend({ focusHolds: true });
  await typeIntoField(send, "#pw", SECRET);
  const focus = calls.find((c) =>
    c.method === "Runtime.callFunctionOn" &&
    !String(c.params.functionDeclaration).includes("document.activeElement"))!;
  const fn = String(focus.params.functionDeclaration);
  expect(fn).toContain("focus");
  expect(fn).toContain("getOwnPropertyDescriptor"); // the native setter, for React
  expect(fn).toContain("'input'");                  // …and the event that syncs it
  // One call, so the guard→insert window (M3) does not grow.
  expect(calls.filter((c) => c.method === "Runtime.callFunctionOn")).toHaveLength(2);
});

test("CLEAR: emptying the field never sends the secret to the page early", async () => {
  const { send, calls } = mkSend({ focusHolds: true });
  await typeIntoField(send, "#pw", SECRET);
  const beforeInsert = calls.slice(0, calls.findIndex((c) => c.method === "Input.insertText"));
  expect(JSON.stringify(beforeInsert)).not.toContain(SECRET);
});

// ── Opt-in synthetic key events ──────────────────────────────────────────────
//
// Input.insertText fires native beforeinput/input but NO keyboard events, so a
// validator wired to keyup sits at "criteria not met" against a correct value
// (a server-rendered password form with a keyup-driven strength meter). Opt-in:
// synthesising key events makes the page believe a human typed, which is a
// capability rather than a courtesy.

const evented = (calls: Call[]) =>
  calls.filter((c) => String(c.params.functionDeclaration ?? "").includes("KeyboardEvent"));

test("EVENTS: nothing extra is dispatched by default", async () => {
  const { send, calls } = mkSend({ focusHolds: true });
  await typeIntoField(send, "#pw", SECRET);
  expect(evented(calls)).toEqual([]);
  expect(calls.map((c) => c.method)).toEqual([
    "Runtime.evaluate", "Runtime.callFunctionOn", "Runtime.callFunctionOn", "Input.insertText",
  ]);
});

test("EVENTS: opting in fires keydown/keypress/keyup/change AFTER the insert", async () => {
  const { send, calls } = mkSend({ focusHolds: true });
  await typeIntoField(send, "#pw", SECRET, undefined, { events: true });
  const burst = evented(calls);
  expect(burst).toHaveLength(1);
  const fn = String(burst[0].params.functionDeclaration);
  for (const t of ["keydown", "keypress", "keyup", "change"]) expect(fn).toContain(t);
  // Strictly after the keystroke — a burst before it would fire against an empty
  // field and tell the validator nothing.
  expect(calls.findIndex((c) => c.method === "Input.insertText"))
    .toBeLessThan(calls.indexOf(burst[0]));
});

test("EVENTS: the synthetic events carry NO key data derived from the secret", async () => {
  const { send, calls } = mkSend({ focusHolds: true });
  await typeIntoField(send, "#pw", SECRET, undefined, { events: true });
  const fn = String(evented(calls)[0].params.functionDeclaration);
  expect(fn).toContain("Unidentified");
  expect(fn).not.toContain(SECRET);
  expect(JSON.stringify(calls.filter((c) => c.method !== "Input.insertText"))).not.toContain(SECRET);
});

test("EVENTS: a burst that throws does NOT report the fill as failed", async () => {
  // The value is already in the field by then. Reporting filled:false would send
  // the caller round again and type it twice.
  const calls: Call[] = [];
  let inserted = false;
  const send: Send = (async (method: string, params: any = {}) => {
    calls.push({ method, params });
    if (method === "Runtime.evaluate") return { result: { objectId: "OBJ-1" } };
    if (method === "Input.insertText") { inserted = true; return { result: {} }; }
    if (method === "Runtime.callFunctionOn") {
      if (String(params.functionDeclaration).includes("KeyboardEvent")) throw new Error("page died");
      const isCheck = String(params.functionDeclaration).includes("document.activeElement");
      return { result: { value: isCheck ? true : undefined } };
    }
    return { result: {} };
  }) as Send;
  await typeIntoField(send, "#pw", SECRET, undefined, { events: true });
  expect(inserted).toBe(true);
});

// ── inspectField: what a field IS, never what it holds ───────────────────────

test("inspectField reports type and visibility, piercing to the real input", async () => {
  const inner = new SEl("input", {}, { type: "password" });
  const host = new SEl("atlas-input", { id: "pw" });
  host.shadowRoot = new SRoot([inner]);
  const doc = new SRoot([host]);
  const send: Send = (async (_m: string, params: any) =>
    ({ result: { value: new Function("document", "getComputedStyle", `return ${params.expression}`)(doc, sstyle) } })) as Send;
  expect(await inspectField(send, "#pw")).toEqual({ type: "password", visible: true });
});

test("inspectField calls an opacity:0 field INVISIBLE — focus alone would not", async () => {
  const el = new SEl("input", { id: "ssn" }, { opacity: "0" });
  const doc = new SRoot([el]);
  const send: Send = (async (_m: string, params: any) =>
    ({ result: { value: new Function("document", "getComputedStyle", `return ${params.expression}`)(doc, sstyle) } })) as Send;
  expect(await inspectField(send, "#ssn")).toEqual({ type: "text", visible: false });
});

test("inspectField returns null for a miss, and never reads .value", async () => {
  const doc = new SRoot([new SEl("input", { id: "dob" })]);
  let expr = "";
  const send: Send = (async (_m: string, params: any) => {
    expr = params.expression;
    return { result: { value: new Function("document", "getComputedStyle", `return ${params.expression}`)(doc, sstyle) } };
  }) as Send;
  expect(await inspectField(send, "#ssn")).toBe(null);
  expect(expr).not.toContain("e.value");
});

// ── Shadow-DOM event propagation: `bubbles` is not enough ────────────────────
//
// Caught by test/live-check.ts, not by anything here: a synthetic event with
// `bubbles:true` alone stops at the shadow root, so the burst reached NO
// document-level listener on precisely the pages piercing exists for — while
// every shim-based test stayed green. `composed` now mirrors what the UA does,
// verified against real Input.dispatchKeyEvent traffic in Chrome 151: key events
// and `input` are composed and cross an open boundary; `change` is not.

test("EVENTS: the key burst is composed, so it escapes an open shadow root", async () => {
  const { send, calls } = mkSend({ focusHolds: true });
  await typeIntoField(send, "#ssn", SECRET, undefined, { events: true });
  const fn = String(evented(calls)[0].params.functionDeclaration);
  expect(fn).toContain("composed:true");
  // …and `change` deliberately is NOT, because a real one is not either.
  expect(fn).toMatch(/change'?,\{bubbles:true\}/);
});

test("EVENTS: the clear's input event is composed too — React sees it through a boundary", async () => {
  const { send, calls } = mkSend({ focusHolds: true });
  await typeIntoField(send, "#pw", SECRET);
  const focus = calls.find((c) =>
    c.method === "Runtime.callFunctionOn" &&
    !String(c.params.functionDeclaration).includes("document.activeElement"))!;
  expect(String(focus.params.functionDeclaration)).toContain("bubbles:true,composed:true");
});
