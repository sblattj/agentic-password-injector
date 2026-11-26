import { expect, test } from "bun:test";
import { lstatSync, mkdtempSync, readFileSync, readlinkSync, statSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";
import { ConfigError, linkKeychains, load, pick, save, toggleTarget, validate, type Registry } from "../src/accounts/config.ts";
import { loginArgs, parseDeviceFlow, parseUsage, parseWhoami } from "../src/accounts/kiro.ts";
import { drive, stateExpr, type DriverDeps, type PageState } from "../src/accounts/drive.ts";
import { homeConflict, loginAccount } from "../src/accounts/login.ts";
import { bestOf } from "../src/accounts/cli.ts";

// ── parsers, against the real kiro-cli 3.5.0 output shapes ──────────────────

test("parseWhoami: logged in vs not", () => {
  const w = parseWhoami("Logged in with IAM Identity Center (https://d-0000000000.awsapps.com/start)\nEmail: a@example.com\n\nProfile:\nKiroProfile-us-east-1\narn:aws:x\n");
  expect(w).toEqual({ loggedIn: true, method: "IAM Identity Center", email: "a@example.com", profile: "KiroProfile-us-east-1" });
  expect(parseWhoami("Not logged in\n")).toEqual({ loggedIn: false });
  expect(parseWhoami("")).toEqual({ loggedIn: false });
});

test("parseUsage: credits line, plan and reset date, with ANSI and thousands separators", () => {
  const u = parseUsage("\x1b[1mEstimated Usage | resets on 2026-12-01 | KIRO POWER\x1b[0m\nCredits (7,752.82 of 10,000 covered in plan), 77.5%\nOverages: Disabled\n");
  expect(u).toEqual({ used: 7752.82, limit: 10000, left: 2247.18, resets: "2026-12-01", plan: "KIRO POWER" });
  expect(parseUsage("the model answered in prose")).toBeNull();
});

test("parseDeviceFlow: URL with user_code and the code", () => {
  const f = parseDeviceFlow("\nConfirm the following code in the browser\nCode: ABCD-EFGH\n\nOpen this URL: https://d-0000000000.awsapps.com/start/#/device?user_code=ABCD-EFGH\n▰▱ Logging in...");
  expect(f).toEqual({ url: "https://d-0000000000.awsapps.com/start/#/device?user_code=ABCD-EFGH", code: "ABCD-EFGH" });
  expect(parseDeviceFlow("Logging in...")).toBeNull();
});

test("loginArgs: pro needs start URL and region, always device flow", () => {
  expect(loginArgs({ license: "pro", startUrl: "https://s.example/start", region: "us-east-2" }))
    .toEqual(["login", "--license", "pro", "--use-device-flow", "--identity-provider", "https://s.example/start", "--region", "us-east-2"]);
  expect(() => loginArgs({ license: "pro" })).toThrow();
  expect(loginArgs({ license: "free" })).toEqual(["login", "--license", "free", "--use-device-flow"]);
});

// ── registry ─────────────────────────────────────────────────────────────────

const reg = (): Registry => ({
  version: 1, active: "me",
  accounts: {
    me: { tool: "kiro", home: homedir(), pinned: true, login: { license: "pro", credential: "kiro-me", signinOrigin: "https://login.example.com" } },
    svc: { tool: "kiro", home: "/tmp/apinj-test/svc/home", login: { license: "pro", credential: "kiro-svc", signinOrigin: "https://login.example.com" } },
  },
});

test("registry: save is 0600 and round-trips; bad shapes refused", () => {
  const p = join(mkdtempSync(join(tmpdir(), "apinj-acc-")), "accounts.json");
  save(reg(), p);
  expect(statSync(p).mode & 0o777).toBe(0o600);
  expect(load(p)).toEqual(reg());
  expect(JSON.parse(readFileSync(p, "utf8")).accounts.svc.home).toBe("/tmp/apinj-test/svc/home");
  expect(() => validate({ version: 2, accounts: {} })).toThrow(ConfigError);
  expect(() => validate({ version: 1, accounts: { "Bad Name": { tool: "kiro", home: "/x" } } })).toThrow(ConfigError);
  expect(() => validate({ version: 1, active: "nobody", accounts: {} })).toThrow(ConfigError);
});

test("pick: explicit name, then APINJ_ACCOUNT, then active", () => {
  const r = reg();
  expect(pick(r, "svc", {})[0]).toBe("svc");
  expect(pick(r, undefined, { APINJ_ACCOUNT: "svc" })[0]).toBe("svc");
  expect(pick(r, undefined, {})[0]).toBe("me");
  expect(() => pick(r, "ghost", {})).toThrow(ConfigError);
});

test("bare swap toggles between exactly two accounts", () => {
  expect(toggleTarget(reg())).toBe("svc");
  expect(toggleTarget({ ...reg(), active: "svc" })).toBe("me");
  const three = reg(); three.accounts.x = { tool: "kiro", home: "/tmp/x" };
  expect(() => toggleTarget(three)).toThrow(ConfigError);
});

test("bestOf: most credits left among logged-in accounts", () => {
  expect(bestOf([
    { name: "me", loggedIn: true, usage: { used: 7752, limit: 10000, left: 2248 } },
    { name: "svc", loggedIn: true, usage: { used: 100, limit: 10000, left: 9900 } },
    { name: "off", loggedIn: false, usage: null },
  ])).toBe("svc");
  expect(bestOf([{ name: "off", loggedIn: false, usage: null }])).toBeNull();
});

// ── the pinned account is never touched ─────────────────────────────────────

test("homeConflict: a non-pinned account may not use the real HOME or a pinned HOME", () => {
  const r = reg();
  expect(homeConflict(r, "svc")).toBeNull();
  r.accounts.svc!.home = homedir();
  expect(homeConflict(r, "svc")).toContain("real HOME");
  const r2 = reg(); r2.accounts.me!.home = "/tmp/apinj-test/me"; r2.accounts.svc!.home = "/tmp/apinj-test/me";
  expect(homeConflict(r2, "svc")).toContain("pinned account 'me'");
});

test("loginAccount refuses a pinned account before running anything", async () => {
  let ran = 0;
  const res = await loginAccount(reg(), "me", { log: () => {}, run: () => { ran++; return { status: 0, out: "" }; } });
  expect(res.ok).toBe(false);
  expect((res as any).reason).toContain("pinned_account");
  expect(ran).toBe(0);
});

// ── the page driver ──────────────────────────────────────────────────────────

const SIGNIN = "https://login.example.com", APPROVE = "https://d-0000000000.awsapps.com";

function fakePage(script: PageState[], over: Partial<DriverDeps> = {}) {
  let i = 0, t = 0;
  const calls: string[] = [];
  let done = false;
  const d: DriverDeps = {
    state: async () => script[Math.min(i, script.length - 1)]!,
    fill: async (f) => { calls.push(`fill:${f}`); i++; return { filled: true }; },
    totp: async () => { calls.push("totp"); i++; return { filled: true }; },
    click: async (text) => {
      calls.push(`click:${text}`);
      const s = script[Math.min(i, script.length - 1)]!;
      if (s.kind === "button" && s.button === text) { i++; if (text === "allow access") done = true; }
      return true;
    },
    sleep: async (ms) => { t += ms; },
    now: () => t,
    finished: () => done,
    ...over,
  };
  return { d, calls };
}

test("drive: username, password, approve, allow, in order, password typed once", async () => {
  const { d, calls } = fakePage([
    { origin: SIGNIN, kind: "username" },
    { origin: SIGNIN, kind: "password" },
    { origin: SIGNIN, kind: "button", button: "yes" },
    { origin: APPROVE, kind: "button", button: "confirm and continue" },
    { origin: APPROVE, kind: "button", button: "allow access" },
    { origin: APPROVE, kind: "approved" },
  ]);
  const r = await drive(d, { signinOrigin: SIGNIN, approveOrigins: [APPROVE], timeoutMs: 60_000, hasTotp: false });
  expect(r).toEqual({ ok: true });
  expect(calls.filter((c) => c.startsWith("fill"))).toEqual(["fill:username", "fill:password"]);
  expect(calls).toContain("click:confirm and continue");
  expect(calls).toContain("click:allow access");
});

test("drive: a second password page stops instead of retrying (lockout guard)", async () => {
  let n = 0;
  const { d } = fakePage([{ origin: SIGNIN, kind: "password" }], {
    fill: async () => { n++; return { filled: true }; },
  });
  const r = await drive(d, { signinOrigin: SIGNIN, approveOrigins: [APPROVE], timeoutMs: 60_000, hasTotp: false });
  expect(r).toEqual({ ok: false, reason: "password_refused", origin: SIGNIN });
  expect(n).toBe(1);
});

test("drive: never fills or clicks on an origin it was not given", async () => {
  const { d, calls } = fakePage([{ origin: "https://evil.example", kind: "password" }]);
  const r = await drive(d, { signinOrigin: SIGNIN, approveOrigins: [APPROVE], timeoutMs: 20_000, hasTotp: false });
  expect(r.ok).toBe(false);
  expect(calls).toEqual([]);
});

test("drive: MFA code page without a stored seed reports mfa_code_required", async () => {
  const { d } = fakePage([{ origin: SIGNIN, kind: "otp" }]);
  const r = await drive(d, { signinOrigin: SIGNIN, approveOrigins: [APPROVE], timeoutMs: 60_000, hasTotp: false });
  expect(r).toEqual({ ok: false, reason: "mfa_code_required", origin: SIGNIN });
});

test("drive: a refused fill surfaces the injector's reason", async () => {
  const { d } = fakePage([{ origin: SIGNIN, kind: "username" }], { fill: async () => ({ filled: false, reason: "origin_mismatch" }) });
  const r = await drive(d, { signinOrigin: SIGNIN, approveOrigins: [APPROVE], timeoutMs: 60_000, hasTotp: false });
  expect(r).toEqual({ ok: false, reason: "username_origin_mismatch", origin: SIGNIN });
});

test("stateExpr reads presence and button text only, never .value of a text field", () => {
  const e = stateExpr(["next"]);
  // b.value is only read for input[type=submit] captions in the button loop.
  expect(e.match(/\.value/g)?.length).toBe(1);
  expect(e).toContain("b.innerText||b.value");
});

test("linkKeychains: account HOME gets Library/Keychains -> the real one; pinned and real HOME untouched", () => {
  const root = mkdtempSync(join(tmpdir(), "apinj-kc-"));
  const real = join(root, "real"), home = join(root, "svc", "home");
  expect(linkKeychains({ tool: "kiro", home }, real)).toBe("linked");
  expect(lstatSync(join(home, "Library", "Keychains")).isSymbolicLink()).toBe(true);
  expect(readlinkSync(join(home, "Library", "Keychains"))).toBe(join(real, "Library", "Keychains"));
  expect(linkKeychains({ tool: "kiro", home }, real)).toBe("present");
  expect(linkKeychains({ tool: "kiro", home: join(root, "p"), pinned: true }, real)).toBe("skipped");
  expect(linkKeychains({ tool: "kiro", home: real }, real)).toBe("skipped");
});

test("drive: a page it cannot read fails as page_unreadable and says why, instead of spinning", async () => {
  const logs: string[] = [];
  const { d } = fakePage([{ origin: SIGNIN, kind: "username" }], {
    state: async () => { throw new Error("no target with id T9"); }, log: (s) => logs.push(s),
  });
  const r = await drive(d, { signinOrigin: SIGNIN, approveOrigins: [APPROVE], timeoutMs: 600_000, hasTotp: false });
  expect(r).toEqual({ ok: false, reason: "page_unreadable", origin: undefined });
  expect(logs).toEqual(["cannot read the page: no target with id T9"]);
});

test("drive: an authenticator push is waited out (not stuck) and its number reported once", async () => {
  const logs: string[] = []; const pushes: (string | undefined)[] = [];
  let reads = 0;
  const { d } = fakePage([{ origin: SIGNIN, kind: "push", number: "99" }], {
    state: async () => (++reads > 40 ? { origin: APPROVE, kind: "button", button: "allow access" } : { origin: SIGNIN, kind: "push", number: "99" }),
    log: (s) => logs.push(s), onPush: (n) => pushes.push(n),
  });
  let done = false;
  d.click = async (t) => { if (t === "allow access") done = true; return true; };
  d.finished = () => done;
  const r = await drive(d, { signinOrigin: SIGNIN, approveOrigins: [APPROVE], timeoutMs: 600_000, hasTotp: false });
  expect(r).toEqual({ ok: true });
  expect(pushes).toEqual(["99"]);
  expect(logs.filter((l) => l.includes("authenticator"))).toEqual(["waiting for approval in the account's authenticator app: enter 99"]);
});

test("drive: with a stored seed, a push prompt is swapped for a typed code", async () => {
  const calls: string[] = [];
  let stage = 0, done = false;
  const d: DriverDeps = {
    state: async () => [
      { origin: SIGNIN, kind: "push", number: "99" } as PageState,
      { origin: SIGNIN, kind: "otp" } as PageState,
      { origin: APPROVE, kind: "button", button: "allow access" } as PageState,
    ][stage]!,
    fill: async () => ({ filled: true }),
    totp: async () => { calls.push("totp"); stage = 2; return { filled: true }; },
    click: async (t) => { calls.push(`click:${t}`); if (t === "use a verification code") stage = 1; if (t === "allow access") done = true; return true; },
    sleep: async () => {}, now: () => 0, finished: () => done,
  };
  const r = await drive(d, { signinOrigin: SIGNIN, approveOrigins: [APPROVE], timeoutMs: 1, hasTotp: true });
  expect(r).toEqual({ ok: true });
  expect(calls.slice(0, 3)).toEqual(["click:i can't use my microsoft authenticator app right now", "click:use a verification code", "totp"]);
});
