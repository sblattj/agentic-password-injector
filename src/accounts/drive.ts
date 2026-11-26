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
// (the IdP's sign-in origin and the device-approval origin), only on buttons
// whose visible text is on a short allowlist. Anything else is waited out and,
// if it persists, reported by origin.

export type PageKind = "username" | "password" | "otp" | "approved" | "button" | "unknown";

export interface PageState { origin: string; kind: PageKind; button?: string }

export interface DriverDeps {
  state: () => Promise<PageState | null>;
  fill: (field: "username" | "password") => Promise<FillResult>;
  totp: () => Promise<FillResult>;
  click: (text: string) => Promise<boolean>;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
  /** Resolves true once the CLI side reports success (e.g. kiro-cli login exited 0). */
  finished: () => boolean;
  log?: (line: string) => void;
}

export interface DriveOptions { signinOrigin: string; approveOrigin: string; timeoutMs: number; hasTotp: boolean }

export type DriveResult = { ok: true } | { ok: false; reason: string; origin?: string };

/** Buttons the driver may press, per page role. Matched on trimmed, case-folded visible text. */
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
    `const allow=${JSON.stringify(buttons)};let button;` +
    `if(kind==='unknown'){for(const b of pierce('button,input[type=submit],[role=button]')){if(!vis(b))continue;` +
    `const t=(b.innerText||b.value||'').trim().toLowerCase();if(allow.includes(t)){button=t;break}}if(button)kind='button'}` +
    `return {origin:location.origin,kind,button}})()`;
}

/** Clicks the first visible button whose text is exactly `text` (already allowlisted by the caller). */
export function clickExpr(text: string): string {
  return `(()=>{const vis=${VISIBLE_FN};const pierce=${ALL_FN};` +
    `for(const b of pierce('button,input[type=submit],[role=button]')){if(!vis(b))continue;` +
    `if((b.innerText||b.value||'').trim().toLowerCase()===${JSON.stringify(text)}){b.click();return true}}return false})()`;
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
  while (d.now() < deadline) {
    if (d.finished()) return { ok: true };
    let s: PageState | null = null;
    try { s = await d.state(); } catch { s = null; }
    if (!s) { await d.sleep(500); continue; }
    lastOrigin = s.origin;
    const onSignin = s.origin === o.signinOrigin;
    const onApprove = s.origin === o.approveOrigin;
    const key = `${s.origin}|${s.kind}|${s.button ?? ""}`;
    const n = (seen.get(key) ?? 0) + 1;
    seen.set(key, n);
    if (n > 12) return { ok: false, reason: `stuck_on_${s.kind}`, origin: s.origin };

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
