import type { FillResult } from "../gated.ts";
import type { Send } from "../cdp.ts";
import { VISIBLE_FN } from "../inject.ts";

/** Page-world: every element matching `sel`, light DOM plus OPEN shadow roots. Inline, never a page global. */
const ALL_FN =
  `((sel)=>{const out=[];const q=[document];for(let i=0;i<q.length;i++){const r=q[i];` +
  `try{out.push(...r.querySelectorAll(sel))}catch(_){}` +
  `try{for(const e of r.querySelectorAll('*'))if(e.shadowRoot)q.push(e.shadowRoot)}catch(_){}}return out})`;

// Drives an IdP sign-in page and the device-code approval page to the end,
// using the injector's own gated fills for every keystroke that carries an
// account fact. This module never sees the password or a one-time code: it asks
// `fill("password")` / `totp()` and gets back {filled, reason?}.
//
// What it does by itself is CLICK, and only on the two origins it was given
// (the IdP's sign-in origin and the device-approval origins), only on buttons
// whose visible text is on a short allowlist. Anything else is waited out and,
// if it persists, reported by origin.

/** `push`: the IdP waits for an authenticator-app approval; `number` is the one to match, if shown. */
export type PageKind = "username" | "password" | "otp" | "push" | "approved" | "button" | "unknown";

export interface PageState { origin: string; kind: PageKind; button?: string; number?: string }

export interface DriverDeps {
  state: () => Promise<PageState | null>;
  fill: (field: "username" | "password") => Promise<FillResult>;
  totp: () => Promise<FillResult>;
  click: (text: string) => Promise<boolean>;
  /** Called once per push-approval prompt (and again if the number changes). */
  onPush?: (number?: string) => void;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
  /** Resolves true once the CLI side reports success (e.g. kiro-cli login exited 0). */
  finished: () => boolean;
  log?: (line: string) => void;
}

export interface DriveOptions {
  signinOrigin: string;
  /** Where the device code is approved: the start-URL origin and the IdC region's sign-in origin. */
  approveOrigins: string[];
  timeoutMs: number;
  hasTotp: boolean;
}

export type DriveResult = { ok: true } | { ok: false; reason: string; origin?: string };

/** Buttons the driver may press, per page role. Matched on trimmed, case-folded visible text. */
/** Consecutive failed page reads before the driver gives up (about 20s at 500ms). */
export const MAX_STATE_ERRORS = 40;

/** With a stored TOTP seed, a push prompt is swapped for a code: these, in order. */
export const OTHER_WAY_LINKS = ["i can't use my microsoft authenticator app right now", "use a verification code"];

export const SIGNIN_BUTTONS = ["next", "sign in", "yes", "verify", "continue"];
export const APPROVE_BUTTONS = ["confirm and continue", "allow access", "allow", "continue"];

/**
 * One expression classifies the page. It reports field PRESENCE and button TEXT
 * only, never an input's value, so it is not a reveal path.
 */
export function stateExpr(buttons: string[]): string {
  return `(()=>{const vis=${VISIBLE_FN};const pierce=${ALL_FN};` +
    `const ins=pierce('input').filter(vis);` +
    `const has=(f)=>ins.some(f);` +
    `const body=(document.body&&document.body.innerText||'').slice(0,4000).toLowerCase();` +
    `let kind='unknown';` +
    `if(has(i=>i.type==='password'))kind='password';` +
    `else if(has(i=>i.autocomplete==='one-time-code'||/^(otc|otp|totp|code)$/i.test(i.name||'')))kind='otp';` +
    `else if(has(i=>i.type==='email'||/^(loginfmt|username|email|login)$/i.test(i.name||'')))kind='username';` +
    `if(kind==='unknown'&&/request approved|you can close this|access (?:allowed|granted)/.test(body))kind='approved';` +
    `let number;if(kind==='unknown'&&/approve (?:the |your )?sign.in request|open your authenticator app/.test(body)){kind='push';` +
    `const n=pierce('#idRichContext_DisplaySign,.displaySign,[data-testid=displaySign]').map(e=>(e.innerText||'').trim()).find(t=>/^\\d{2,3}$/.test(t));if(n)number=n}` +
    `const allow=${JSON.stringify(buttons)};let button;` +
    `if(kind==='unknown'){for(const b of pierce('button,input[type=submit],[role=button]')){if(!vis(b))continue;` +
    `const t=(b.innerText||b.value||'').trim().toLowerCase();if(allow.includes(t)){button=t;break}}if(button)kind='button'}` +
    `return {origin:location.origin,kind,button,number}})()`;
}

/** Clicks the first visible button whose text is exactly `text` (already allowlisted by the caller). */
export function clickExpr(text: string): string {
  return `(()=>{const vis=${VISIBLE_FN};const pierce=${ALL_FN};` +
    `for(const b of pierce('button,input[type=submit],[role=button],a,[data-value]')){if(!vis(b))continue;` +
    `if((b.innerText||b.value||'').trim().toLowerCase().replace(/[\u2018\u2019]/g,"'")===${JSON.stringify(text)}){b.click();return true}}return false})()`;
}

export async function readState(send: Send, buttons: string[]): Promise<PageState | null> {
  const r = await send<{ result: { value?: PageState } }>("Runtime.evaluate", { expression: stateExpr(buttons), returnByValue: true });
  return r?.result?.value ?? null;
}

export async function clickButton(send: Send, text: string): Promise<boolean> {
  const r = await send<{ result: { value?: boolean } }>("Runtime.evaluate", { expression: clickExpr(text), returnByValue: true });
  return r?.result?.value === true;
}

/**
 * The state machine. Two hard limits protect the account: the password is typed
 * at most ONCE per run (a second password page means it was refused, and
 * retrying invites a lockout), and the same page seen too many times stops the
 * run instead of looping.
 */
export async function drive(d: DriverDeps, o: DriveOptions): Promise<DriveResult> {
  const deadline = d.now() + o.timeoutMs;
  const seen = new Map<string, number>();
  let passwordTyped = 0, usernameTyped = 0, codeTyped = 0;
  let lastOrigin = "";
  let stateErrors = 0;
  let otherWay = 0;
  const errSeen = new Set<string>();
  while (d.now() < deadline) {
    if (d.finished()) return { ok: true };
    let s: PageState | null = null;
    try { s = await d.state(); } catch (e) {
      // CDP errors carry no page content; log each distinct one once so a broken
      // connection is visible instead of a silent spin until the timeout.
      const m = String((e as Error)?.message ?? e).slice(0, 200);
      if (!errSeen.has(m)) { errSeen.add(m); d.log?.(`cannot read the page: ${m}`); }
      if (++stateErrors >= MAX_STATE_ERRORS) return { ok: false, reason: "page_unreadable", origin: lastOrigin || undefined };
      await d.sleep(500);
      continue;
    }
    stateErrors = 0;
    if (!s) { await d.sleep(500); continue; }
    lastOrigin = s.origin;
    const onSignin = s.origin === o.signinOrigin;
    const onApprove = o.approveOrigins.includes(s.origin);
    const key = `${s.origin}|${s.kind}|${s.button ?? ""}`;
    const n = (seen.get(key) ?? 0) + 1;
    seen.set(key, n);
    // A push approval is waited out to the overall timeout: a person approves it on their phone.
    if (n > 12 && s.kind !== "push") return { ok: false, reason: `stuck_on_${s.kind}`, origin: s.origin };
    if (s.kind === "push" && onSignin && o.hasTotp && otherWay < OTHER_WAY_LINKS.length) {
      // Prefer a code we can type over a phone tap: walk the "sign in another way" links.
      for (; otherWay < OTHER_WAY_LINKS.length; otherWay++) {
        if (await d.click(OTHER_WAY_LINKS[otherWay]!)) { d.log?.(`chose: ${OTHER_WAY_LINKS[otherWay]}`); await d.sleep(1200); }
      }
      continue;
    }
    if (s.kind === "push" && onSignin) {
      const said = `push:${s.number ?? ""}`;
      if (!errSeen.has(said)) {
        errSeen.add(said);
        d.log?.(`waiting for approval in the account's authenticator app${s.number ? `: enter ${s.number}` : ""}`);
        d.onPush?.(s.number);
      }
      await d.sleep(1500);
      continue;
    }

    if (s.kind === "approved" && onApprove) {
      // The CLI polls the token endpoint; give it a moment to notice.
      await d.sleep(1000);
      continue;
    }
    if (!onSignin && !onApprove) { await d.sleep(750); continue; }

    if (onSignin && s.kind === "username") {
      if (usernameTyped >= 2) return { ok: false, reason: "username_refused", origin: s.origin };
      const r = await d.fill("username");
      if (!r.filled) return { ok: false, reason: `username_${r.reason ?? "not_filled"}`, origin: s.origin };
      usernameTyped++;
      d.log?.("typed the username");
      await d.sleep(300);
      await pressFirst(d, SIGNIN_BUTTONS.slice(0, 2));
      await d.sleep(1500);
      continue;
    }
    if (onSignin && s.kind === "password") {
      if (passwordTyped >= 1) return { ok: false, reason: "password_refused", origin: s.origin };
      const r = await d.fill("password");
      if (!r.filled) return { ok: false, reason: `password_${r.reason ?? "not_filled"}`, origin: s.origin };
      passwordTyped++;
      d.log?.("typed the password");
      await d.sleep(300);
      await pressFirst(d, ["sign in", "next", "verify"]);
      await d.sleep(2000);
      continue;
    }
    if (onSignin && s.kind === "otp") {
      if (!o.hasTotp) return { ok: false, reason: "mfa_code_required", origin: s.origin };
      if (codeTyped >= 2) return { ok: false, reason: "mfa_code_refused", origin: s.origin };
      const r = await d.totp();
      if (!r.filled) return { ok: false, reason: `totp_${r.reason ?? "not_filled"}`, origin: s.origin };
      codeTyped++;
      d.log?.("typed the one-time code");
      await d.sleep(300);
      await pressFirst(d, ["verify", "sign in", "next"]);
      await d.sleep(2000);
      continue;
    }
    if (s.kind === "button" && s.button) {
      const allowed = onSignin ? SIGNIN_BUTTONS : APPROVE_BUTTONS;
      if (allowed.includes(s.button)) {
        await d.click(s.button);
        d.log?.(`pressed "${s.button}" on ${s.origin}`);
        await d.sleep(1500);
        continue;
      }
    }
    await d.sleep(750);
  }
  return d.finished() ? { ok: true } : { ok: false, reason: "timeout", origin: lastOrigin || undefined };
}

async function pressFirst(d: DriverDeps, texts: string[]): Promise<void> {
  for (const t of texts) if (await d.click(t)) return;
}

/**
 * What an unrecognized page shows, for the log: title, headings and button
 * captions only. Never an input's value.
 */
export const DESCRIBE_EXPR = `(()=>{const all=${ALL_FN};const t=(e)=>(e.innerText||'').trim().replace(/\\s+/g,' ').slice(0,80);` +
  `return JSON.stringify({title:document.title,path:location.pathname.slice(0,40),` +
  `heads:all('h1,h2,[role=heading],#loginHeader,.text-title,[data-testid=title]').map(t).filter(Boolean).slice(0,4),` +
  `text:all('#idDiv_SAOTCAS_Description,#idRichContext_DisplaySign,.text-body,[role=alert]').map(t).filter(Boolean).slice(0,3),` +
  `buttons:all('button,input[type=submit],input[type=button],[role=button]').map(b=>(b.innerText||(b.type!=='text'&&b.type!=='password'?b.value:'')||'').trim().slice(0,40)).filter(Boolean).slice(0,10)})})()`;

export async function describePage(send: Send): Promise<string> {
  const r = await send<{ result: { value?: string } }>("Runtime.evaluate", { expression: DESCRIBE_EXPR, returnByValue: true });
  return r.result.value ?? "";
}
