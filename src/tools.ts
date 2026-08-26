import { CdpError, getLoaderId, getOrigin, resolveTarget, withConn, type Send } from "./cdp.ts";
import { confirmInjection, confirmSecretInjection } from "./consent.ts";
import { PUBLIC_SUFFIXES } from "./domain.ts";
import { decideGate } from "./gate.ts";
import { VISIBLE_FN, detectLoginFields, inspectField, typeIntoField, type TypeOptions } from "./inject.ts";
import { originMatches } from "./origin.ts";
import { SECRET_FORMATS, isSecretFormat, shape, type SecretFormat } from "./secret.ts";
import { totpCode } from "./totp.ts";
import { resolveCredential, type Resolved } from "./vault/index.ts";
import { keychainHasTotp, keychainSecret, keychainTotpSeed, type SecretEntry } from "./vault/keychain.ts";
import type { Cred } from "./vault/arc.ts";

export interface ToolSchema { name: string; description: string; inputSchema: Record<string, unknown>; }
export const MANIFEST: ToolSchema[] = [];
export const TOOLS: Record<string, (args: unknown) => Promise<unknown>> = {};

// ── Injected dependencies ────────────────────────────────────────────────────
// Every side-effecting collaborator goes through this record so the security
// gate can be tested without a live browser, a live vault, or a real dialog.
export interface Deps {
  resolveCredential: (domain: string, opts: { name?: string }) => Promise<Resolved>;
  resolveTarget: (tabId: string) => Promise<{ wsUrl: string; url: string }>;
  withConn: <T>(wsUrl: string, fn: (send: Send) => Promise<T>) => Promise<T>;
  getOrigin: (send: Send) => Promise<string>;
  /** Browser-side identity of the CURRENT document load — the anti-TOCTOU token. */
  getLoaderId: (send: Send) => Promise<string>;
  /** Keychain-only, by NAME. A named secret must never resolve through Arc — see `fillSecret`. */
  resolveSecret: (name: string) => Promise<SecretEntry | null>;
  /** Prompts with the credential's BOUND origin; the caller domain is context only. */
  confirmInjection: (boundOrigin: string, username: string, requestedDomain: string) => Promise<boolean>;
  /** Prompts with the BOUND origin and the entry name — what is typed, and where. */
  confirmSecret: (boundOrigin: string, secretName: string) => Promise<boolean>;
  detectLoginFields: (send: Send) => Promise<{ user?: string; pass?: string; ambiguous?: boolean }>;
  /** `guard` is re-asserted INSIDE, immediately before the keystroke (M3). */
  typeIntoField: (send: Send, selector: string, value: string, guard?: Guard, opts?: TypeOptions) => Promise<void>;
  probeFields: (send: Send, attr: string, token: string, opts?: ProbeOptions) => Promise<FieldInfo[]>;
  /** The resolved field's type and visibility. Never its value. */
  inspectField: (send: Send, selector: string) => Promise<{ type: string; visible: boolean } | null>;
  totpCode: (seed: string) => string;
  keychainHasTotp: (name: string) => boolean;
  keychainTotpSeed: (name: string) => string | null;
}

export const REAL_DEPS: Deps = {
  resolveCredential,
  resolveSecret: keychainSecret,
  resolveTarget,
  withConn,
  getOrigin,
  getLoaderId,
  confirmInjection: (origin, u, requested) => confirmInjection(origin, u, requested),
  confirmSecret: (origin, name) => confirmSecretInjection(origin, name),
  detectLoginFields,
  typeIntoField,
  probeFields,
  inspectField,
  totpCode: (seed) => totpCode(seed),
  keychainHasTotp,
  keychainTotpSeed,
};

// ── Shapes ───────────────────────────────────────────────────────────────────
// A reason is always one of a fixed vocabulary. Raw error text NEVER escapes a
// tool, because a decrypt/keychain error message can carry fragments of state we
// have not audited. Distinct reasons keep "vault is locked" from ever reading
// like "that password was wrong".
export type FillResult = { filled: boolean; submitted?: boolean; reason?: string };

const fail = (reason: string): FillResult => ({ filled: false, reason });

/**
 * The origin a credential is BOUND to. Never derived from the caller-supplied
 * domain: doing so would make the gate compare the tab against a value the caller
 * chose, i.e. no binding at all — `login({domain:"evil.com", name:"mybank"})` on
 * evil.com would pass. Arc creds always carry a real origin; Keychain creds carry
 * whatever was stored in the entry's comment attribute, and an empty one FAILS
 * CLOSED at the call site with `no_origin_binding`.
 */
function savedOriginFor(cred: Cred): string {
  return cred.origin;
}

// ── Caller-supplied domain validation ────────────────────────────────────────
// `PUBLIC_SUFFIXES` (imported from ./domain.ts) is the list of suffixes that are
// only ever the TAIL of a registrable name. A lookup keyed on one of them matches
// EVERY saved login under it, which is how `list_credentials({domain:"com"})`
// turned a metadata-only, consent-free tool into a bank-enumeration oracle (I3):
// sweep `com`/`net`/`co.uk`/… and learn which institutions the user banks with,
// under which usernames, with no dialog and no origin gate — prime material for a
// follow-on phishing prompt.
//
// The DATA is shared with the vault-side guard; the FUNCTIONS stay separate, so a
// bug in either check is still caught by the other.

const LABEL_RE = /^(?:xn--)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/**
 * Is `domain` a plausible REGISTRABLE domain the caller may look up?
 *
 * Deliberately syntactic and conservative. It is not trying to prove the domain
 * exists — it is closing the entry point so a caller cannot hand the vault a key
 * that matches everything. The vault's own `hostMatches` is tightened separately
 * as defence in depth; neither is allowed to be the only guard.
 */
export function isValidDomain(raw: string): boolean {
  const d = raw.trim().toLowerCase();
  if (!d || d.length > 253) return false;
  // No scheme, port, path, credentials, wildcard or whitespace — a domain only.
  if (/[^a-z0-9.-]/.test(d)) return false;
  if (d.startsWith(".") || d.endsWith(".") || d.includes("..")) return false;
  const labels = d.split(".");
  // A single label is either a bare TLD ("com") or a hostname with no registrable
  // part; both match far too much to be a credential key.
  if (labels.length < 2) return false;
  if (labels.some((l) => !l || l.length > 63 || !LABEL_RE.test(l))) return false;
  // The TLD must look like a TLD: alphabetic (or punycode), at least two chars.
  const tld = labels[labels.length - 1];
  if (tld.length < 2 || !(/^[a-z]+$/.test(tld) || tld.startsWith("xn--"))) return false;
  // "co.uk" is a suffix, not a site.
  if (PUBLIC_SUFFIXES.has(d)) return false;
  return true;
}

/** Maps a thrown vault error onto a fixed reason code without leaking its message. */
function secretFailReason(e: unknown): string {
  const code = (e as CdpError)?.code;
  return code === "vault_locked" || code === "decrypt_failed" ? code : "decrypt_failed";
}

/**
 * A vault that ERRORED is not a vault that came back empty. A Keychain access
 * denial or an Arc `Login Data` SQLITE_BUSY must never present as `not_found`,
 * which reads like "you have no such credential" and invites a retry loop.
 */
function vaultFailReason(e: unknown): string {
  return (e as CdpError)?.code === "vault_locked" ? "vault_locked" : "vault_error";
}

/**
 * Thrown by `guard` to abort a fill from deep inside `run` without typing.
 * Carries a fixed reason code, never a message that could echo page state.
 */
class GateAbort extends Error {
  constructor(public reason: string) { super(reason); }
}

/**
 * A pre-keystroke check: resolves if the tab is still what was authorised, else
 * throws. Passed down into `typeIntoField` so the LAST thing before the keystroke
 * is another assertion, not a stale one from three round-trips ago (M3).
 */
export type Guard = () => Promise<void>;

// Reason codes raised as exceptions from inside `run` that must survive the outer
// catch verbatim instead of collapsing to `tab_unavailable` — the user needs to
// see WHY nothing was typed.
const PASSTHROUGH_REASONS = new Set(["focus_lost", "navigated_during_consent"]);

/**
 * Resolve → connect → **origin-check** → consent → gate → **re-check before every
 * keystroke**.
 *
 * INVARIANT #1: the live origin is read from the tab (never cached, never taken
 * from the target list URL) and compared BEFORE `confirmInjection` is called, so
 * a mismatched tab cannot even raise a dialog — an attacker-controlled page must
 * not be able to make the user answer a prompt about someone else's domain.
 *
 * INVARIANT #1b (C1): the check is repeated immediately before EVERY keystroke.
 * `confirmInjection` is a blocking osascript dialog with `giving up after 60`, so
 * a single pre-dialog check leaves a ~60-second window in which the tab can be
 * navigated away — by a page timer, a meta-refresh, a frame navigating the top,
 * or, most directly, the same prompt-injected model issuing `navigate_page`
 * through its own browser MCP. The user truthfully approved `mybank.com`; the
 * password landed on `evil.com`. Re-checking the captured STRING (what
 * `decideGate` does) authorises nothing new, so `guard` re-reads the LIVE origin
 * and compares the main frame's `loaderId` — a same-origin string can survive a
 * navigation, and an in-flight cross-origin load can commit between an origin
 * read and the keystroke, but any document commit mints a new loaderId. Both must
 * be unchanged; anything else aborts BEFORE the keystroke with
 * `navigated_during_consent`.
 */
async function gated(
  d: Deps,
  args: { tabId?: unknown; domain?: unknown; name?: unknown },
  run: (send: Send, cred: Cred, guard: Guard) => Promise<FillResult>,
): Promise<FillResult> {
  const tabId = typeof args.tabId === "string" ? args.tabId : "";
  const domain = typeof args.domain === "string" ? args.domain : "";
  const name = typeof args.name === "string" ? args.name : undefined;
  if (!tabId) return fail("tab_unavailable");
  // A MISSING argument and a BAD argument are different mistakes, and neither is
  // `not_found` — that reads as "no such credential" and sends the caller hunting
  // for a vault entry that was never the problem.
  if (!domain) return fail("domain_required");
  if (!isValidDomain(domain)) return fail("bad_domain");

  let r: Resolved;
  try { r = await d.resolveCredential(domain, { name }); }
  catch (e) { return fail(vaultFailReason(e)); }
  if ("found" in r) return fail("not_found");
  const cred = r.cred;

  // Fail closed before anything else: a credential with no bound origin cannot be
  // gated, so it is not injectable. Checked here, ahead of the connection and the
  // dialog, so an unbound credential can never raise a prompt.
  const savedOrigin = savedOriginFor(cred);
  if (!savedOrigin) return fail("no_origin_binding");

  // The human authorises the BOUND origin — the same value the gate enforces.
  return gatedOnOrigin(
    d, tabId, savedOrigin,
    () => d.confirmInjection(savedOrigin, cred.username, domain),
    (send, guard) => run(send, cred, guard),
  );
}

/**
 * Everything after "which secret" is settled: connect, origin-check, consent,
 * gate, and hand `run` a guard that re-asserts before every keystroke.
 *
 * Split out of `gated` so a NAMED SECRET gets these guarantees verbatim rather
 * than in a second, subtly-different copy. What differs between a credential and
 * a secret is entirely upstream of here — which vault answers, what the dialog
 * says, which field is legal — and none of that belongs in the TOCTOU path.
 */
async function gatedOnOrigin(
  d: Deps,
  tabId: string,
  savedOrigin: string,
  consent: () => Promise<boolean>,
  run: (send: Send, guard: Guard) => Promise<FillResult>,
): Promise<FillResult> {
  let target: { wsUrl: string };
  try { target = await d.resolveTarget(tabId); } catch { return fail("tab_unavailable"); }

  try {
    return await d.withConn(target.wsUrl, async (send) => {
      let tabOrigin: string;
      let loaderId: string;
      try {
        tabOrigin = await d.getOrigin(send);
        loaderId = await d.getLoaderId(send);
      } catch { return fail("tab_unavailable"); }

      // Pre-consent short-circuit: never prompt about a tab we would refuse anyway.
      if (!originMatches(tabOrigin, savedOrigin)) return fail("origin_mismatch");
      // Fail closed: with no loaderId there is no way to prove the document did
      // not change under the dialog, so the fill is unverifiable, not "fine".
      if (!loaderId) return fail("tab_unavailable");

      /**
       * Called immediately before EVERY keystroke. Both facts must still hold:
       * the live origin still matches what the human authorised, AND the document
       * is the same load it was when they authorised it.
       */
      const guard: Guard = async () => {
        let liveOrigin: string;
        let liveLoader: string;
        try {
          liveOrigin = await d.getOrigin(send);
          liveLoader = await d.getLoaderId(send);
        } catch { throw new GateAbort("tab_unavailable"); }
        if (liveOrigin !== tabOrigin || !originMatches(liveOrigin, savedOrigin)) {
          throw new GateAbort("navigated_during_consent");
        }
        if (!liveLoader || liveLoader !== loaderId) {
          throw new GateAbort("navigated_during_consent");
        }
      };

      const allow = await consent();
      const g = decideGate({ tabOrigin, savedOrigin, allow });
      if (!g.ok) return fail(g.reason);

      // The dialog just blocked for up to a minute. Nothing below may assume the
      // tab is still the tab, hence the post-consent re-check and the per-keystroke
      // ones inside `run`.
      try { await guard(); } catch (e) { return fail((e as GateAbort).reason); }

      return await run(send, guard);
    });
  } catch (e) {
    // Nothing past the gate should throw, but a socket death mid-flight must not
    // surface a raw message — collapse to a fixed reason.
    if (e instanceof GateAbort) return fail(e.reason);
    const code = (e as CdpError)?.code;
    if (code === "vault_locked" || code === "decrypt_failed" || PASSTHROUGH_REASONS.has(code)) return fail(code);
    return fail("tab_unavailable");
  }
}

// ── list_credentials ─────────────────────────────────────────────────────────
export interface CredentialMeta { origin: string; username: string; backend: string; has_totp: boolean }

/** Metadata only — no password, no seed, no getSecret call. */
export async function listCredentials(args: unknown, d: Deps = REAL_DEPS): Promise<{ credentials: CredentialMeta[]; reason?: string }> {
  const a = (args ?? {}) as { domain?: unknown; name?: unknown };
  const domain = typeof a.domain === "string" ? a.domain : "";
  const name = typeof a.name === "string" ? a.name : undefined;
  // The vault backends are lookup-by-domain, not enumerable, so a listing is
  // scoped to a domain rather than dumping every saved login. That scoping is
  // ONLY meaningful if the key cannot match everything — see `isValidDomain`.
  // This tool has no consent dialog and no origin gate (correctly: it is
  // metadata-only), which makes it the cheapest sweep surface in the server, so
  // the validation has to happen here rather than downstream.
  if (!domain) return { credentials: [], reason: "domain_required" };
  if (!isValidDomain(domain)) return { credentials: [], reason: "bad_domain" };
  let r: Resolved;
  try { r = await d.resolveCredential(domain, { name }); }
  catch (e) { return { credentials: [], reason: vaultFailReason(e) }; }
  if ("found" in r) return { credentials: [] };
  // The TOTP probe is a SECOND vault call, and since it learned to distinguish a
  // fault from a miss it can THROW (`vault_locked`) — outside the resolve above's
  // catch. An uncaught throw here escapes the tool as a raw MCP error instead of
  // the fixed reason vocabulary every other path returns, so it is mapped the
  // same way: a locked keychain is a status, not a crash.
  let has_totp: boolean;
  try { has_totp = d.keychainHasTotp(name ?? domain); }
  catch (e) { return { credentials: [], reason: vaultFailReason(e) }; }
  return {
    credentials: [{
      // Metadata only, and metadata must still render for an unbound credential —
      // reporting origin "" is how the user SEES that it needs a `-j` origin.
      origin: r.cred.origin,
      username: r.cred.username,
      backend: r.backend,
      has_totp,
    }],
  };
}

// ── Field probing ────────────────────────────────────────────────────────────
// The page reports candidate inputs; the CHOICE is made here in Node as a pure
// function, mirroring `chooseFields` in inject.ts. That keeps the selection logic
// unit-testable instead of buried in a serialized expression string.

export interface FieldInfo {
  sel: string; type: string; name: string; id: string;
  placeholder: string; label: string; autocomplete: string; focused: boolean;
}

export const OTP_ATTR = "data-apinj-otp";
export const USER_ATTR = "data-apinj-user";
export const SECRET_ATTR = "data-apinj-secret";

/**
 * Both defaults are the narrow, existing behaviour. `fill_credential` and
 * `fill_totp` keep exactly the candidate set they had: widening it would change
 * which pages they call AMBIGUOUS, and their ambiguity refusals are load-bearing.
 */
export interface ProbeOptions {
  /** Also enumerate inputs inside open shadow roots (see `PIERCE_FN`). */
  deep?: boolean;
  /** Include `type="password"` inputs among the candidates. */
  includePassword?: boolean;
}

// A stamp value must be UNIQUE PER CALL. A shared literal (`="1"`) leaves the
// previous call's attribute on the DOM, so a later probe's selector resolves to
// the STALE element and the code is typed into the wrong field while reporting
// success. Each probe also strips its own prior stamps before re-stamping.
let stampSeq = 0;
export function nextToken(kind: string): string { return `${kind}${++stampSeq}`; }

export function probeExpr(attr: string, token: string, opts: ProbeOptions = {}): string {
  const a = JSON.stringify(attr), t = JSON.stringify(token);
  // The roots to enumerate. Shallow is `[document]` and issues no `'*'` query at
  // all, so the shallow expression is byte-for-byte the shape it always was.
  const roots = opts.deep
    ? `(()=>{const rs=[document];for(let i=0;i<rs.length;i++){let all=[];` +
      `try{all=[...rs[i].querySelectorAll('*')]}catch(_){}` +
      `for(const e of all)if(e.shadowRoot)rs.push(e.shadowRoot)}return rs})()`
    : `[document]`;
  // A password box is excluded by default because the two tools that probe want
  // a NON-password field; `fill_secret` needs them, since a secret whose entry
  // does not say `kind=text` may only ever land in one.
  const typeFilter = opts.includePassword ? `e.type!=='hidden'` : `e.type!=='password'&&e.type!=='hidden'`;
  // `deepActive` matches the deep-activeElement walk in inject.ts's FOCUS_CHECK:
  // with an open shadow root `document.activeElement` is the HOST, so a flat
  // comparison reports `focused:false` for the very field the user is typing in.
  const deepActive = `(()=>{let x=document.activeElement;` +
    `while(x&&x.shadowRoot&&x.shadowRoot.activeElement)x=x.shadowRoot.activeElement;return x})()`;
  return `(()=>{const rts=${roots};` +
    `rts.forEach(r=>{try{r.querySelectorAll('['+${a}+']').forEach(e=>e.removeAttribute(${a}))}catch(_){}});` +
    // Same honest visibility test as the password path: `offsetParent` alone lets
    // an opacity:0 / 0x0 decoy earlier in DOM order win, and this probe feeds the
    // username, the live OTP code and now a named secret.
    `const vis=${VISIBLE_FN};const act=${deepActive};` +
    `const els=rts.flatMap(r=>[...r.querySelectorAll('input')]).filter(e=>vis(e)&&${typeFilter});` +
    `return els.map((e,i)=>{const v=${t}+'-'+i;e.setAttribute(${a},v);` +
    `return {sel:'['+${a}+'=\"'+v+'\"]',type:e.type||'text',name:e.name||'',id:e.id||'',` +
    `placeholder:e.placeholder||'',label:e.getAttribute('aria-label')||'',` +
    `autocomplete:e.autocomplete||'',focused:e===act}})})()`;
}

export async function probeFields(send: Send, attr: string, token: string, opts: ProbeOptions = {}): Promise<FieldInfo[]> {
  const r = await send<{ result: { value?: FieldInfo[] } }>("Runtime.evaluate", {
    expression: probeExpr(attr, token, opts),
    returnByValue: true,
  });
  return r?.result?.value ?? [];
}

const text = (f: FieldInfo) => `${f.name} ${f.id} ${f.placeholder} ${f.label}`;

// Deliberately NOT matching a bare "code": "Zip code" and "Promo code" are
// ordinary fields that routinely precede the real OTP box in DOM order, and
// typing a live one-time code into one is a disclosure, not a typo.
const OTP_RE = /one.?time|\botp|\btotp|2fa|two.?factor|\bmfa\b|verification.?code|authenticat|auth.?code|security.?code|passcode/i;

export function chooseOtpField(f: FieldInfo[]): string | null {
  const explicit = f.find((x) => x.autocomplete === "one-time-code");
  if (explicit) return explicit.sel;
  const named = f.find((x) => OTP_RE.test(text(x)));
  if (named) return named.sel;
  const focused = f.find((x) => x.focused);
  if (focused) return focused.sel;
  return f.length === 1 ? f[0].sel : null;
}

const USER_RE = /user|email|login|ident|account|\bphone\b/i;

export function chooseUsernameField(f: FieldInfo[]): string | null {
  const explicit = f.find((x) => x.autocomplete === "username" || x.autocomplete === "email");
  if (explicit) return explicit.sel;
  const named = f.find((x) => USER_RE.test(text(x)));
  if (named) return named.sel;
  // Last resort: accept an UNLABELLED input only when it is the sole candidate.
  // Taking the first one in DOM order would type the username into a site-search
  // or promo-code box that happens to render earlier — the same
  // wrong-field-reported-as-success shape the OTP stamp fix closed. Ambiguity
  // must refuse, not guess.
  const typed = f.filter((x) => x.type === "email" || x.type === "text");
  return typed.length === 1 ? typed[0].sel : null;
}

/**
 * Which field a NAMED SECRET may be auto-detected into. Sole candidate, or
 * refuse.
 *
 * Unlike `chooseOtpField` there is deliberately NO naming heuristic and NO
 * focus tiebreak. An OTP box announces itself (`autocomplete="one-time-code"`,
 * "verification code") and the code it holds expires in thirty seconds. An SSN
 * announces nothing, and does not expire — the cost of guessing wrong is the
 * value rendered in a visible box on a page the human trusts, which is precisely
 * what the default `sel=deny` exists to prevent. Focus is worse than useless
 * here: it is one line of attacker JavaScript on the matched origin, so honouring
 * it would hand back the field control the caller was refused.
 *
 * Sole-candidate is the one rule an attacker cannot exploit in that direction:
 * adding an input creates AMBIGUITY, and ambiguity refuses. A real identity form
 * has many text boxes and will therefore refuse — correctly. That is what
 * `sel=allow` is for, and setting it is a human's decision.
 */
export function chooseSecretField(
  f: FieldInfo[],
  opts: { kindText: boolean },
): { sel?: string; ambiguous?: boolean } {
  // `f` is already visible-only and non-hidden. Without `kind=text` a secret may
  // land in a password box and nowhere else — the same protection `chooseFields`
  // gets for free by keying on `type === "password"`.
  const cands = opts.kindText ? f : f.filter((x) => x.type === "password");
  if (cands.length === 0) return {};
  if (cands.length > 1) return { ambiguous: true };
  return { sel: cands[0].sel };
}

// ── fill_credential ──────────────────────────────────────────────────────────
export async function fillCredential(args: unknown, d: Deps = REAL_DEPS): Promise<FillResult> {
  const a = (args ?? {}) as { field?: unknown; events?: unknown };
  const field = a.field === "username" || a.field === "password" ? a.field : null;
  if (!field) return fail("bad_field");
  const events = Boolean(a.events);

  return gated(d, (args ?? {}) as any, async (send, cred, guard) => {
    const fields = await d.detectLoginFields(send);

    // Gate on the REQUESTED field only. Identifier-first flows (Google, Microsoft)
    // show a username box with no password field on the page yet — demanding a
    // password field here would break the exact case per-field filling exists for.
    if (field === "username") {
      // detectLoginFields anchors on the password input, so it yields nothing at
      // all on an identifier-first page; probe for the username box directly.
      let sel = fields.user ?? null;
      if (!sel) sel = chooseUsernameField(await d.probeFields(send, USER_ATTR, nextToken("user")));
      if (!sel) return fail("no_username_field");
      await guard();
      await d.typeIntoField(send, sel, cred.username, guard, { events });
      return { filled: true };
    }

    if (fields.ambiguous) return fail("ambiguous_password_field");
    if (!fields.pass) return fail("no_password_field");
    let secret: string;
    try { secret = cred.getSecret(); } catch (e) { return fail(secretFailReason(e)); }
    try {
      await guard();
      await d.typeIntoField(send, fields.pass, secret, guard, { events });
    } finally { secret = ""; }
    return { filled: true };
  });
}

// ── login ────────────────────────────────────────────────────────────────────
const SUBMIT_EXPR =
  `(()=>{const f=document.querySelector('input[type=password]')?.form;` +
  `if(!f)return false;const b=f.querySelector('[type=submit],button[type=submit],button');` +
  `if(!b)return false;b.click();return true})()`;

/** One origin check, ONE consent dialog, then username + password + optional submit. */
export async function login(args: unknown, d: Deps = REAL_DEPS): Promise<FillResult> {
  const submit = Boolean((args as { submit?: unknown } | null)?.submit);
  const events = Boolean((args as { events?: unknown } | null)?.events);
  return gated(d, (args ?? {}) as any, async (send, cred, guard) => {
    const fields = await d.detectLoginFields(send);
    if (fields.ambiguous) return fail("ambiguous_password_field");
    if (!fields.pass) return fail("no_password_field");

    let secret: string;
    try { secret = cred.getSecret(); } catch (e) { return fail(secretFailReason(e)); }
    try {
      // A guard before EACH keystroke, not one before the pair: the username fill
      // is itself a round-trip the page can navigate under.
      if (fields.user) {
        await guard();
        await d.typeIntoField(send, fields.user, cred.username, guard, { events });
      }
      await guard();
      await d.typeIntoField(send, fields.pass, secret, guard, { events });
    } finally {
      secret = ""; // drop the plaintext the moment the keystrokes are out
    }

    let submitted = false;
    if (submit) {
      // The fill was itself several round-trips; a navigation that lands after
      // the password and before the click would have this `.click()` fire on an
      // attacker document (no secret at risk, but the human authorised a submit
      // on THEIR bank, not a click on whatever replaced it). Guard, then click.
      await guard();
      const r = await send<{ result: { value?: boolean } }>("Runtime.evaluate", { expression: SUBMIT_EXPR, returnByValue: true });
      submitted = r?.result?.value === true;
    }
    return { filled: true, submitted };
  });
}

// ── fill_totp ────────────────────────────────────────────────────────────────

export async function fillTotp(args: unknown, d: Deps = REAL_DEPS): Promise<FillResult> {
  const a = (args ?? {}) as { selector?: unknown; domain?: unknown; name?: unknown };
  const selector = typeof a.selector === "string" && a.selector ? a.selector : null;
  const domain = typeof a.domain === "string" ? a.domain : "";
  const name = typeof a.name === "string" ? a.name : undefined;

  return gated(d, (args ?? {}) as any, async (send, _cred, guard) => {
    // The seed is read here, used here, and dropped here. It is never returned,
    // never logged, and the generated code is never returned either.
    const seed = d.keychainTotpSeed(name ?? domain);
    if (!seed) return fail("no_totp");

    let sel = selector;
    if (!sel) sel = chooseOtpField(await d.probeFields(send, OTP_ATTR, nextToken("otp")));
    if (!sel) return fail("no_otp_field");

    let code: string;
    try { code = d.totpCode(seed); } catch { return fail("bad_totp_seed"); }
    try {
      await guard();
      await d.typeIntoField(send, sel, code, guard);
    } finally { code = ""; }
    return { filled: true };
  });
}

// ── fill_secret ──────────────────────────────────────────────────────────────
//
// A named secret is not a credential: an SSN, a freeze PIN, a date of birth, an
// account number. It has no username, it rarely goes into a password box, and
// the same nine digits are wanted in five different shapes. What it shares with
// a credential is the part that matters — a mandatory origin binding, a consent
// dialog, and a guard re-asserted before every keystroke.
//
// The reference implementation this replaces took an arbitrary CSS selector,
// because a human typed it. This server assumes the caller may be steered by
// page content, so selector control is DENIED by default and granted per entry,
// at storage time, by the human who stores it. That single flag is the whole
// difference between the two threat models; everything else here is plumbing.

/**
 * A secret name, validated at the entry point.
 *
 * Independent of `consent.ts:safeSecretName` on purpose, exactly as
 * `isValidDomain` is independent of `safeRequestedDomain`: this one keeps a
 * hostile string out of `security` and out of the reason vocabulary, that one
 * keeps it out of the sentence a human reads. Neither is allowed to be the only
 * guard.
 */
const SECRET_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
export function isValidSecretName(raw: string): boolean {
  return SECRET_NAME_RE.test(raw);
}

/** `shape()` failures, mapped onto the fixed vocabulary without their message. */
function shapeFailReason(e: unknown): string {
  const code = (e as CdpError)?.code;
  return code === "format_mismatch" || code === "bad_format" ? code : "format_mismatch";
}

export async function fillSecret(args: unknown, d: Deps = REAL_DEPS): Promise<FillResult> {
  const a = (args ?? {}) as { tabId?: unknown; name?: unknown; selector?: unknown; format?: unknown; events?: unknown };
  const tabId = typeof a.tabId === "string" ? a.tabId : "";
  const name = typeof a.name === "string" ? a.name : "";
  const selector = typeof a.selector === "string" && a.selector ? a.selector : null;
  const events = Boolean(a.events);

  if (!tabId) return fail("tab_unavailable");
  // `name` is the vault key here, the way `domain` is for a credential. Missing
  // and malformed are different mistakes, and neither is `not_found`.
  if (!name) return fail("name_required");
  if (!isValidSecretName(name)) return fail("bad_name");
  const rawFormat = a.format === undefined ? "raw" : a.format;
  if (!isSecretFormat(rawFormat)) return fail("bad_format");
  const format: SecretFormat = rawFormat;

  // KEYCHAIN ONLY, never the credential chain. `resolveCredential` would try Arc
  // first and hand back a saved LOGIN whose username happens to equal the name —
  // a different value than the one the human authorised, from a backend that
  // carries no `sel`/`kind` flags. That is the substitution `resolveCredentialWith`
  // rule 1 forbids, arriving through the back door.
  let entry: SecretEntry | null;
  try { entry = await d.resolveSecret(name); }
  catch (e) { return fail(vaultFailReason(e)); }
  if (!entry) return fail("not_found");

  const savedOrigin = entry.origin;
  if (!savedOrigin) return fail("no_origin_binding");

  // The two capabilities a stored entry can grant. Both default to DENY, and
  // both are read from the vault — never from the arguments.
  const selAllowed = entry.flags.sel === "allow";
  const kindText = entry.flags.kind === "text";

  // Refused before the connection and before the dialog: a caller that supplies
  // a selector for an entry that does not permit one must not be able to make a
  // human answer a prompt about it.
  if (selector && !selAllowed) return fail("selector_not_allowed");

  return gatedOnOrigin(
    d, tabId, savedOrigin,
    () => d.confirmSecret(savedOrigin, name),
    async (send, guard) => {
      let sel = selector;
      if (!sel) {
        // Deep, and password boxes included: the chooser needs to SEE a password
        // field to pick it when `kind=text` is absent, and to see the other
        // candidates in order to refuse when there is more than one.
        const fields = await d.probeFields(send, SECRET_ATTR, nextToken("sec"), { deep: true, includePassword: true });
        const c = chooseSecretField(fields, { kindText });
        if (c.ambiguous) return fail("ambiguous_secret_field");
        sel = c.sel ?? null;
      }
      if (!sel) return fail("no_secret_field");

      // Re-read the field the injection will actually resolve to, on BOTH paths.
      // On the selector path this is where `kind` is enforced at all; on the
      // probe path it re-checks the same element through the same piercing
      // resolver the keystroke will use, so the type that was approved is the
      // type that gets typed into.
      const info = await d.inspectField(send, sel);
      if (!info) return fail("no_secret_field");
      // An opacity:0 input still takes focus, so the focus verification alone
      // does not rule out an invisible capture box (I5).
      if (!info.visible) return fail("field_not_visible");
      if (!kindText && info.type !== "password") return fail("kind_not_allowed");

      let value: string;
      try { value = shape(entry.getSecret(), format); }
      catch (e) {
        // A vault fault and a shape refusal are different failures and must not
        // collapse: one means "grant Keychain access", the other means "the
        // stored value is not what this format needs".
        const code = (e as CdpError)?.code;
        return fail(code === "vault_locked" || code === "vault_error" ? code : shapeFailReason(e));
      }
      try {
        await guard();
        await d.typeIntoField(send, sel, value, guard, { events });
      } finally { value = ""; }
      return { filled: true };
    },
  );
}

// ── Registration ─────────────────────────────────────────────────────────────
const TAB = {
  tabId: { type: "string", description: "CDP target id of the tab to inject into" },
  domain: { type: "string", description: "Domain of the saved credential, e.g. github.com" },
  name: { type: "string", description: "Optional Keychain entry name when several credentials share a domain" },
} as const;

const EVENTS_PROP = {
  type: "boolean",
  description:
    "Fire synthetic keydown/keypress/keyup/change after the insert. Set this when a page's validator " +
    "keys off keyup and shows 'criteria not met' against a value that is actually correct.",
} as const;

function register(name: string, description: string, inputSchema: Record<string, unknown>, fn: (args: unknown) => Promise<unknown>) {
  MANIFEST.push({ name, description, inputSchema });
  TOOLS[name] = fn;
}

register(
  "list_credentials",
  "List saved credential METADATA for a domain (origin, username, backend, has_totp). Never returns a password or TOTP seed.",
  { type: "object", properties: { domain: TAB.domain, name: TAB.name }, required: ["domain"], additionalProperties: false },
  (args) => listCredentials(args),
);

register(
  "fill_credential",
  "Type ONE field (username or password) of a saved credential into the tab's login form, after an origin match and user consent. Returns only {filled, reason?}.",
  {
    type: "object",
    properties: {
      ...TAB,
      field: { type: "string", enum: ["username", "password"], description: "Which field to fill" },
      events: EVENTS_PROP,
    },
    required: ["tabId", "domain", "field"],
    additionalProperties: false,
  },
  (args) => fillCredential(args),
);

register(
  "login",
  "Fill username and password into the tab's login form behind a single origin match and one consent prompt, optionally submitting. Returns only {filled, submitted, reason?}.",
  {
    type: "object",
    properties: {
      ...TAB,
      submit: { type: "boolean", description: "Click the form's submit button after filling" },
      events: EVENTS_PROP,
    },
    required: ["tabId", "domain"],
    additionalProperties: false,
  },
  (args) => login(args),
);

register(
  "fill_totp",
  "Generate the current TOTP code from the saved seed and type it into the one-time-code field. Never returns the seed or the code.",
  {
    type: "object",
    properties: { ...TAB, selector: { type: "string", description: "Optional CSS selector for the one-time-code input" } },
    required: ["tabId", "domain"],
    additionalProperties: false,
  },
  (args) => fillTotp(args),
);

register(
  "fill_secret",
  "Type a NAMED secret (SSN, PIN, account number) from the Keychain into a field, after an origin match " +
  "and user consent. The entry is apinj:<name>; its stored origin is the binding. A caller-supplied " +
  "selector is honoured only if the entry was stored with sel=allow, and a non-password field only if it " +
  "was stored with kind=text. Returns only {filled, reason?} — never the value, its length, or a mask.",
  {
    type: "object",
    properties: {
      tabId: TAB.tabId,
      name: { type: "string", description: "Keychain entry name; the secret is stored under apinj:<name>" },
      selector: {
        type: "string",
        description: "Optional CSS selector for the target field (pierces open shadow roots). " +
          "Refused with selector_not_allowed unless the entry was stored with sel=allow.",
      },
      format: {
        type: "string",
        enum: [...SECRET_FORMATS],
        description: "Shape the stored value before typing: raw (default), dashed (XXX-XX-XXXX), " +
          "last4, first3, mid2. Everything but raw requires a nine-digit stored value.",
      },
      events: EVENTS_PROP,
    },
    required: ["tabId", "name"],
    additionalProperties: false,
  },
  (args) => fillSecret(args),
);
