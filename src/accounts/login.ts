import { homedir } from "node:os";
import { resolve } from "node:path";
import { withConn, resolveTarget, type Send } from "../cdp.ts";
import { fillCredential, fillTotp, REAL_DEPS, type Deps } from "../tools.ts";
import { keychainHasTotp, keychainLookup } from "../vault/keychain.ts";
import type { FillResult } from "../gated.ts";
import { homeOf, linkKeychains, type Account, type Registry } from "./config.ts";
import { APPROVE_BUTTONS, SIGNIN_BUTTONS, clickButton, describePage, pickAccount, drive, readState, type DriveResult, type PageState } from "./drive.ts";
import { launchAccountBrowser, openTab, waitForFirstLoad } from "./browser.ts";
import { startDeviceLogin, whoami, type Runner, realRunner } from "./kiro.ts";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";

export const ENDPOINT_NAME = "apinj_account";

/**
 * The two fills the driver may ask for, routed through the injector's own
 * gated tools: origin bound by the Keychain entry, loaderId guard before every
 * keystroke, secret zeroed in a finally. Only {filled, reason?} comes back.
 */
export function makeFillers(tabRef: string, domain: string, credential: string, deps: Deps = REAL_DEPS) {
  return {
    fill: (field: "username" | "password"): Promise<FillResult> =>
      fillCredential({ tabId: tabRef, domain, name: credential, field }, deps),
    totp: (): Promise<FillResult> => fillTotp({ tabId: tabRef, domain, name: credential }, deps),
  };
}

/** A non-pinned account may not share a HOME with a pinned one, or with the real HOME. */
export function homeConflict(r: Registry, name: string): string | null {
  const a = r.accounts[name]!;
  const h = homeOf(a);
  if (a.pinned) return null;
  if (h === resolve(homedir())) return "its home is your real HOME; register that account as --pinned instead";
  for (const [n, b] of Object.entries(r.accounts)) {
    if (n !== name && b.pinned && homeOf(b) === h) return `its home is the home of pinned account '${n}'`;
  }
  return null;
}

export interface LoginOptions { headed?: boolean; timeoutS?: number; log: (s: string) => void; run?: Runner }

export type LoginOutcome =
  | { ok: true; already?: boolean; email?: string }
  | { ok: false; reason: string; origin?: string };

export async function loginAccount(r: Registry, name: string, o: LoginOptions): Promise<LoginOutcome> {
  const a: Account = r.accounts[name]!;
  const run = o.run ?? realRunner;
  if (a.pinned) return { ok: false, reason: "pinned_account (log it in yourself; this tool never logs a pinned account in or out)" };
  const conflict = homeConflict(r, name);
  if (conflict) return { ok: false, reason: `home_conflict: ${conflict}` };
  const l = a.login;
  if (!l?.credential || !l.signinOrigin) return { ok: false, reason: "login.credential and login.signinOrigin are required for auto-login" };
  const home = homeOf(a);
  linkKeychains(a);

  // Identity the account must end up as: the Keychain entry's username (attributes only, no secret).
  const cred = await keychainLookup(l.credential).catch(() => null);
  if (!cred) return { ok: false, reason: `no Keychain entry apinj:${l.credential} (run the save-credentials step first)` };
  const expect = cred.username.toLowerCase();

  const before = whoami(home, run);
  if (before.loggedIn && before.email?.toLowerCase() === expect) return { ok: true, already: true, email: before.email };

  const timeoutS = o.timeoutS ?? 300;
  const proc = startDeviceLogin(home, l, timeoutS);
  let browser: Awaited<ReturnType<typeof launchAccountBrowser>> | null = null;
  try {
    const flow = await Promise.race([proc.flow, Bun.sleep(30_000).then(() => null)]);
    if (!flow) return { ok: false, reason: "kiro-cli login printed no device URL in 30s" };
    const approveOrigins = [new URL(flow.url).origin, ...(l.region ? [`https://${l.region}.signin.aws`] : [])];
    o.log(`device flow started (approval on ${approveOrigins.join(" or ")})`);
    const profile = a.browserProfile ? homeOfPath(a.browserProfile) : resolve(home, "..", "browser");
    browser = await launchAccountBrowser(profile, { headed: o.headed });
    process.env.CDP_ENDPOINTS = `${ENDPOINT_NAME}=${browser.base}`;
    const tabId = await openTab(browser.base, flow.url);
    await waitForFirstLoad(browser.base, tabId);
    const tabRef = `endpoint:${ENDPOINT_NAME}/${tabId}`;
    const domain = new URL(l.signinOrigin).hostname;
    const fillers = makeFillers(tabRef, domain, l.credential);
    let exited: number | null | undefined;
    proc.done.then((c) => { exited = c; });

    const onTab = <T>(fn: (send: Send) => Promise<T>) => resolveTarget(tabRef).then((t) => withConn(t.wsUrl, fn));
    const res: DriveResult = await drive({
      state: () => onTab<PageState | null>((s) => readState(s, [...new Set([...SIGNIN_BUTTONS, ...APPROVE_BUTTONS])])),
      fill: fillers.fill,
      totp: fillers.totp,
      click: (t) => onTab((s) => clickButton(s, t)).catch(() => false),
      pick: (u) => onTab((s) => pickAccount(s, u)).catch(() => false as const),
      reopenDevice: () => onTab((s) => s("Page.navigate", { url: flow.url })).then(() => undefined, () => undefined),
      sleep: (ms) => Bun.sleep(ms),
      now: () => Date.now(),
      finished: () => exited !== undefined,
      log: o.log,
    }, { signinOrigin: new URL(l.signinOrigin).origin, signinAltOrigins: (l.signinAltOrigins ?? []).map((u) => new URL(u).origin), approveOrigins, timeoutMs: timeoutS * 1000, hasTotp: keychainHasTotp(l.credential), expectUser: expect });

    if (!res.ok && res.reason.startsWith("stuck_on_")) {
      const seen = await onTab(describePage).catch(() => "");
      if (seen) o.log(`page it stopped on: ${seen}`);
    }
    const code = await Promise.race([proc.done, Bun.sleep(15_000).then(() => "pending" as const)]);
    if (!res.ok) return res;
    if (code !== 0) return { ok: false, reason: `kiro-cli login exited ${code ?? `on ${proc.signal() ?? "a signal"}`}` };
  } finally {
    proc.kill();
    browser?.stop();
  }

  const after = whoami(home, run);
  if (!after.loggedIn) return { ok: false, reason: "login finished but whoami says not logged in" };
  if (after.email?.toLowerCase() !== expect) {
    // Wrong identity in this HOME: undo it here (never a pinned HOME, checked above).
    spawnSync(process.env.APINJ_KIRO_CLI || "kiro-cli", ["logout"], { cwd: tmpdir(), env: { ...process.env, HOME: home } });
    return { ok: false, reason: "wrong_identity (logged this HOME back out)" };
  }
  return { ok: true, email: after.email };
}

function homeOfPath(p: string) { return homeOf({ tool: "kiro", home: p }); }
