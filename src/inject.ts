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
    expression: `document.querySelector(${JSON.stringify(selector)})`,
    returnByValue: false,
  });
  if (!r.result.objectId) throw new CdpError("tab_unavailable", `no element for ${selector}`);
  return r.result.objectId;
}

/**
 * Returns TRUE only when the resolved element is the one that will receive the
 * next `Input.insertText`, i.e. it IS `document.activeElement` and it can accept
 * the text. Boolean-only — it never reads `value`, so it is not a reveal path.
 */
const FOCUS_CHECK =
  "function(){return this===document.activeElement&&!this.readOnly&&!this.disabled}";

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
 * resolve → focus → verify → **guard** → insert. Any navigation anywhere in the
 * window now aborts with `navigated_during_consent`, having typed nothing.
 */
export async function typeIntoField(
  send: Send,
  selector: string,
  value: string,
  guard: PreInsertGuard = NO_GUARD,
): Promise<void> {
  const objectId = await resolveObjectId(send, selector);
  await send("Runtime.callFunctionOn", {
    objectId,
    functionDeclaration: "function(){this.scrollIntoView({block:'center'});this.focus&&this.focus();}",
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
