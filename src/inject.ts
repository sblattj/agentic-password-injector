import type { Send } from "./cdp.ts";
import { CdpError } from "./cdp.ts";

export interface InputInfo { sel: string; type: string; visible: boolean; idx: number; }

/**
 * A page-world expression fragment that decides whether `e` is a field a HUMAN
 * could actually be looking at and typing into.
 *
 * `offsetParent` is NOT a visibility test (I5). It is truthy for an `opacity:0`
 * input, a `clip-path`-ed input, a 0x0 input and an off-screen input, and it is
 * *falsy* for any `position:fixed` element. A decoy password input hidden with
 * `opacity:0` earlier in DOM order therefore counted as visible and won — a
 * credential-capture primitive for anyone with script on the matched origin.
 *
 * Real test: non-zero rendered box, not `visibility:hidden`/`display:none`, and
 * non-transparent. Guarded with `typeof` so the same string also evaluates under
 * a minimal test shim.
 */
const VISIBLE_FN =
  `(e=>{try{` +
  `const r=e.getBoundingClientRect?e.getBoundingClientRect():null;` +
  `if(r&&(r.width<=0||r.height<=0))return false;` +
  `if(!r&&!e.offsetParent)return false;` +
  `if(typeof getComputedStyle==='function'){const s=getComputedStyle(e);` +
  `if(s.visibility==='hidden'||s.visibility==='collapse'||s.display==='none')return false;` +
  `if(Number(s.opacity)<=0)return false;}` +
  `return true}catch(_){return false}})`;

export { VISIBLE_FN };

/**
 * A page-world expression fragment: `PIERCE_FN(sel)` resolves `sel` the way a
 * human's click does, crossing OPEN shadow roots.
 *
 * `document.querySelector` stops at a shadow boundary, so for a field inside an
 * open shadow root it finds only the HOST — Experian's `<atlas-input>`, Angular
 * Material, Salesforce Lightning Web Components. Focus then lands on the host,
 * `Input.insertText` goes wherever focus really is, and the tool either refuses
 * or types somewhere unintended. So: try the light DOM, then walk open shadow
 * roots breadth-first; and if what we land on is a host rather than a field,
 * descend to the first `input`/`textarea` inside it.
 *
 * SECURITY: this is an INLINE expression, never a `window.__pierce` global.
 * Installing the resolver on the page hands the page the ability to redefine it
 * — a script on the matched origin that pre-defines `window.__pierce` chooses
 * which element every subsequent injection targets, which is exactly the field
 * control the caller is refused. The reference script did install a global; that
 * part is deliberately not ported.
 *
 * Closed shadow roots are not reachable and are not meant to be: `shadowRoot` is
 * null for them, the BFS skips them, and the caller gets a clean refusal rather
 * than a guess.
 */
const PIERCE_FN =
  `((sel)=>{` +
  `const deepen=(el)=>{if(!el)return null;` +
  `try{if(el.matches&&el.matches('input,textarea'))return el}catch(_){}` +
  `try{if(el.shadowRoot){const i=el.shadowRoot.querySelector('input,textarea');if(i)return i}}catch(_){}` +
  `return el};` +
  `try{const d=document.querySelector(sel);if(d)return deepen(d)}catch(_){return null}` +
  `const q=[document];` +
  `for(let i=0;i<q.length;i++){const r=q[i];` +
  `try{const h=r.querySelector&&r.querySelector(sel);if(h)return deepen(h)}catch(_){}` +
  `let all=[];try{all=r.querySelectorAll?[...r.querySelectorAll('*')]:[]}catch(_){}` +
  `for(const e of all)if(e.shadowRoot)q.push(e.shadowRoot)}` +
  `return null})`;

export { PIERCE_FN };

/**
 * Choose the login fields, refusing on ambiguity rather than guessing.
 *
 * Taking `vis.find(type === "password")` — the FIRST visible password input in
 * DOM order — is only safe if "visible" is honest and if there is exactly one
 * candidate. Both halves matter: the honest visibility test (above) removes the
 * hidden decoy, and this ambiguity refusal removes the case where two genuinely
 * visible password boxes exist and the tool would otherwise pick one at random
 * and report `filled:true`. Mirrors `chooseUsernameField`'s discipline.
 */
export function chooseFields(inputs: InputInfo[]): { user?: string; pass?: string; ambiguous?: boolean } {
  const vis = inputs.filter((i) => i.visible);
  const passes = vis.filter((i) => i.type === "password");
  if (passes.length > 1) return { ambiguous: true };
  const pass = passes[0];
  if (!pass) return {};
  const user = [...vis].reverse().find((i) => i.idx < pass.idx && (i.type === "email" || i.type === "text"));
  return user ? { user: user.sel, pass: pass.sel } : { pass: pass.sel };
}

async function resolveObjectId(send: Send, selector: string): Promise<string> {
  const r = await send<{ result: { objectId?: string } }>("Runtime.evaluate", {
    expression: `${PIERCE_FN}(${JSON.stringify(selector)})`,
    returnByValue: false,
  });
  if (!r.result.objectId) throw new CdpError("tab_unavailable", `no element for ${selector}`);
  return r.result.objectId;
}

/**
 * Returns TRUE only when the resolved element is the one that will receive the
 * next `Input.insertText`, i.e. it IS the deep active element and it can accept
 * the text. Boolean-only — it never reads `value`, so it is not a reveal path.
 *
 * DEEP `activeElement` (gotcha 3): with an open shadow root,
 * `document.activeElement` reports the HOST, not the focused inner input, so a
 * flat identity check against the pierced element is false whenever piercing
 * actually did something. Left flat, piercing and focus-verification are
 * mutually exclusive — every shadow-DOM field refuses with `focus_lost`, and the
 * tempting "fix" is to drop the check that makes injection safe at all. So walk
 * down through `shadowRoot.activeElement` and compare at the bottom.
 */
const FOCUS_CHECK =
  "function(){let a=document.activeElement;" +
  "while(a&&a.shadowRoot&&a.shadowRoot.activeElement)a=a.shadowRoot.activeElement;" +
  "return a===this&&!this.readOnly&&!this.disabled}";

/**
 * Scroll into view, focus, and EMPTY the field, in one round-trip.
 *
 * Clearing matters because `Input.insertText` inserts at the caret rather than
 * replacing: a box that already holds text gets the secret CONCATENATED onto it,
 * and the tool reports `filled:true` over a value the site will reject — or, on
 * a segmented input being re-filled, over a value that is silently wrong. It is
 * done through the native `value` setter rather than `el.value = ''` so React's
 * tracked value is invalidated, then an `input` event lets the framework observe
 * the empty state; without that, a controlled component re-renders the old text
 * straight back over the caret.
 *
 * One round-trip, not two, so the guard→insert window (M3) does not grow: the
 * verification below must stay the LAST thing before the keystroke.
 */
const FOCUS_AND_CLEAR =
  "function(){this.scrollIntoView({block:'center'});this.focus&&this.focus();" +
  "try{const p=(typeof HTMLTextAreaElement!=='undefined'&&this instanceof HTMLTextAreaElement)" +
  "?HTMLTextAreaElement:HTMLInputElement;" +
  "const s=Object.getOwnPropertyDescriptor(p.prototype,'value').set;s.call(this,'');" +
  "this.dispatchEvent(new Event('input',{bubbles:true,composed:true}))}catch(_){}}";

/**
 * Post-insert synthetic events, dispatched only when the caller asks for them.
 *
 * `Input.insertText` fires native `beforeinput` and `input` but NO keyboard
 * events. A validation widget wired to `keyup` — plain jQuery/vanilla, still
 * everywhere — therefore never re-evaluates, and sits at "criteria not met"
 * against a DOM value that is perfectly correct. Observed on ID.me's password
 * form, 2026-08-26: all four strength criteria read invalid against a valid
 * 24-character value that would have submitted fine.
 *
 * Opt-in, because synthesising key events is a capability rather than a
 * courtesy: it makes the page believe a human typed. The events carry NO key
 * data (`key:'Unidentified'`, no `code`, no `charCode`), so a handler reading
 * `event.key` learns nothing about the secret — only that something was typed,
 * which the `input` event already told it.
 *
 * `composed` MATCHES what the UA does, verified against real `Input.dispatchKeyEvent`
 * traffic in Chrome 151: key events and `input` are `composed:true` and cross an
 * open shadow boundary; `change` is not, and stops at the shadow root. `bubbles`
 * alone is NOT enough — a synthetic `bubbles:true` event dispatched on an input
 * two shadow roots deep reached no document-level listener at all, so the burst
 * silently did nothing on exactly the pages that motivated the piercing work.
 * Synthesising an event that propagates differently from the real one is its own
 * lie, so `change` is deliberately left un-composed rather than "fixed".
 */
const POST_INSERT_EVENTS =
  "function(){try{for(const t of ['keydown','keypress','keyup'])" +
  "this.dispatchEvent(new KeyboardEvent(t,{bubbles:true,composed:true,key:'Unidentified'}))}catch(_){}" +
  "try{this.dispatchEvent(new Event('change',{bubbles:true}))}catch(_){}}";

/**
 * What a field IS, without reading what it holds: its `type` and whether a human
 * could see it. Both are needed BEFORE a named secret is typed — `type` because
 * a secret may only land in a non-password box when its vault entry says so, and
 * `visible` because an `opacity:0` input can still take focus, so the focus
 * verification alone does not rule out an invisible capture box.
 *
 * Never reads `value`. Same honest visibility test as the detection path (I5).
 */
export async function inspectField(
  send: Send,
  selector: string,
): Promise<{ type: string; visible: boolean } | null> {
  const expr =
    `(()=>{const e=${PIERCE_FN}(${JSON.stringify(selector)});if(!e)return null;` +
    `return{type:String(e.type||'text').toLowerCase(),visible:${VISIBLE_FN}(e)}})()`;
  const r = await send<{ result: { value?: { type: string; visible: boolean } | null } }>(
    "Runtime.evaluate",
    { expression: expr, returnByValue: true },
  );
  return r?.result?.value ?? null;
}

/**
 * A pre-keystroke re-assertion: resolves if the tab is still the document the
 * human authorised, throws otherwise. Structurally identical to `tools.ts`'s
 * `Guard`; declared here so `inject.ts` stays free of any import from `tools.ts`
 * (which imports this module).
 */
export type PreInsertGuard = () => Promise<void>;

/** Callers with no gate to assert (tests, non-gated paths) get a no-op. */
const NO_GUARD: PreInsertGuard = async () => {};

/**
 * Type `value` into the element `selector` resolves to.
 *
 * SECURITY (I4): `Input.insertText` is dispatched at the PAGE, not at an
 * objectId — it lands wherever focus currently is. `.focus()` can silently fail
 * (readonly/disabled/unfocusable) or be undone by an `onfocus`/`focusin` handler
 * or an async focus-steal firing between the two CDP round-trips. Without a
 * check, the password or the live OTP goes into a DIFFERENT input — potentially a
 * visible `text` box that renders it on screen and into the next snapshot the
 * model takes — while the tool returns `{filled:true}`.
 *
 * So focus, then VERIFY in a separate round-trip immediately before inserting.
 * The separate round-trip is deliberate: a check bundled into the focus call
 * cannot observe a steal that happens after that call returns. Failure throws
 * `focus_lost` and NOTHING is typed.
 *
 * SECURITY (M3): the caller's origin/loaderId guard runs *before* this function,
 * and there are three CDP round-trips between that call and the keystroke. Two of
 * them are self-protecting — a document commit destroys the resolved objectId's
 * execution context, so `callFunctionOn` errors and nothing is typed — but the
 * guard→`resolveObjectId` sub-window is a real gap: a commit landing there leaves
 * a *valid* objectId on the NEW document (the selector stamp is deterministic and
 * pre-placeable by an attacker page), and the insert would land on it. So the
 * guard is re-asserted HERE, as the last thing before `Input.insertText`:
 * resolve → focus+clear → verify → **guard** → insert. Any navigation anywhere
 * in the window now aborts with `navigated_during_consent`, having typed nothing.
 */
export interface TypeOptions {
  /** Fire a synthetic keydown/keypress/keyup/change burst after the insert. */
  events?: boolean;
}

export async function typeIntoField(
  send: Send,
  selector: string,
  value: string,
  guard: PreInsertGuard = NO_GUARD,
  opts: TypeOptions = {},
): Promise<void> {
  const objectId = await resolveObjectId(send, selector);
  await send("Runtime.callFunctionOn", {
    objectId,
    functionDeclaration: FOCUS_AND_CLEAR,
    returnByValue: true,
  });
  const ok = await send<{ result: { value?: boolean } }>("Runtime.callFunctionOn", {
    objectId,
    functionDeclaration: FOCUS_CHECK,
    returnByValue: true,
  });
  if (ok?.result?.value !== true) {
    throw new CdpError("focus_lost", `focus did not land on ${selector}`);
  }
  // Last possible moment. Throws (GateAbort) rather than returning, so there is
  // no branch in which the insert below runs on an unverified document.
  await guard();
  await send("Input.insertText", { text: value }); // real keystrokes; value never returned
  // After the secret is out. Carries no secret itself, so no guard is needed —
  // and a failure here must not be reported as "nothing was typed", because the
  // keystroke above already landed.
  if (opts.events) {
    try {
      await send("Runtime.callFunctionOn", {
        objectId,
        functionDeclaration: POST_INSERT_EVENTS,
        returnByValue: true,
      });
    } catch { /* the value is in the field; a missed validator nudge is cosmetic */ }
  }
}

export const DETECT_EXPR =
  `(()=>{const vis=${VISIBLE_FN};const els=[...document.querySelectorAll('input')];` +
  `return els.map((e,idx)=>{e.setAttribute('data-apinj','i'+idx);` +
  `return {sel:'[data-apinj="i'+idx+'"]',type:(e.type||'text'),visible:vis(e),idx};});})()`;

export async function detectLoginFields(send: Send): Promise<{ user?: string; pass?: string; ambiguous?: boolean }> {
  const r = await send<{ result: { value: InputInfo[] } }>("Runtime.evaluate", {
    expression: DETECT_EXPR,
    returnByValue: true,
  });
  return chooseFields(r.result.value ?? []);
}
