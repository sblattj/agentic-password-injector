import { expect, test } from "bun:test";
import type { Deps } from "../src/tools.ts";
import type { Send } from "../src/cdp.ts";
import { makeFillers } from "../src/accounts/login.ts";
import { drive, type PageState } from "../src/accounts/drive.ts";

// The account manager never reads a secret itself: every keystroke that carries
// one goes through the injector's gated fills. This proves it end to end over the
// driver: with a sentinel password and TOTP seed behind the fills, the sentinel
// reaches typeIntoField and appears in NO log line, return value or thrown text.

const SENTINEL = "S3NT1NEL-acct-do-not-leak";
const SEED = "S3NT1NEL-SEED-JBSWY3DPEHPK3PXP";
const CODE = "918273";
const SIGNIN = "https://login.example.com", APPROVE = "https://d-0000000000.awsapps.com";
const send: Send = (async () => ({ result: {} })) as Send;

function deps(typed: string[]): Deps {
  return {
    resolveCredential: async () => ({ cred: { origin: SIGNIN, username: "svc@example.com", getSecret: () => SENTINEL }, backend: "keychain" }),
    resolveSecret: async () => null,
    resolveTarget: async () => ({ wsUrl: "ws://stub", url: `${SIGNIN}/` }),
    withConn: async (_w, fn) => fn(send),
    getOrigin: async () => SIGNIN,
    getLoaderId: async () => "L1",
    confirmInjection: async () => true,
    confirmSecret: async () => true,
    detectLoginFields: async () => ({ user: "#u", pass: "#p" }),
    typeIntoField: async (_s, _sel, v) => { typed.push(v); },
    probeFields: async (_s, attr, token) => [{ sel: `[${attr}="${token}-0"]`, type: "text", name: "otc", id: "", placeholder: "", label: "code", autocomplete: "one-time-code", focused: true } as any],
    inspectField: async () => ({ type: "password", visible: true }),
    totpCode: () => CODE,
    keychainHasTotp: () => true,
    keychainTotpSeed: () => SEED,
  };
}

test("login driver over the injector fills: secret typed, never logged or returned", async () => {
  const typed: string[] = [];
  const logs: string[] = [];
  const f = makeFillers("T1", "login.example.com", "kiro-svc", deps(typed));
  const script: PageState[] = [
    { origin: SIGNIN, kind: "username" }, { origin: SIGNIN, kind: "password" }, { origin: SIGNIN, kind: "otp" },
    { origin: APPROVE, kind: "button", button: "allow access" },
  ];
  let i = 0, t = 0, done = false;
  const results: unknown[] = [];
  const res = await drive({
    state: async () => script[Math.min(i, script.length - 1)]!,
    fill: async (field) => { const r = await f.fill(field); results.push(r); i++; return r; },
    totp: async () => { const r = await f.totp(); results.push(r); i++; return r; },
    click: async (text) => { if (text === "allow access") done = true; return true; },
    sleep: async (ms) => { t += ms; }, now: () => t, finished: () => done,
    log: (s) => logs.push(s),
  }, { signinOrigin: SIGNIN, approveOrigins: [APPROVE], timeoutMs: 60_000, hasTotp: true }).catch((e) => ({ error: String(e) }));

  expect(res).toEqual({ ok: true });
  // Non-vacuous: the secrets DID reach the page.
  expect(typed).toContain(SENTINEL);
  expect(typed).toContain(CODE);
  const visible = JSON.stringify({ res, results, logs });
  for (const s of [SENTINEL, SEED, CODE]) expect(visible).not.toContain(s);
});

test("fill refusal path: reason only, no secret", async () => {
  const typed: string[] = [];
  const d = deps(typed);
  d.getOrigin = async () => "https://evil.example";
  const f = makeFillers("T1", "login.example.com", "kiro-svc", d);
  const r = await f.fill("password");
  expect(r).toEqual({ filled: false, reason: "origin_mismatch" });
  expect(typed).toEqual([]);
  expect(JSON.stringify(r)).not.toContain(SENTINEL);
});
