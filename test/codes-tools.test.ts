import { afterAll, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CdpError, type Send } from "../src/cdp.ts";
import { messagesSource } from "../src/codes/messages.ts";
import type { CodeMessage, CodeSource } from "../src/codes/types.ts";
import {
  CODE_LOOKBACK_MAX_MS, MANIFEST, fillEmailCode, fillSmsCode, resolveSince, type CodeDeps, type Deps,
} from "../src/tools.ts";

const CODE = "731904";
const BODY = `Example: your verification code is ${CODE}. Don't share it.`;
const SENDER = "+15550009999";
const ORIGIN = "https://login.example.com";
const NOW = 1_800_000_000_000;

function mk(opts: { origin?: string; msgs?: CodeMessage[] | (() => CodeMessage[]); allow?: boolean; srcErr?: string; fields?: boolean; loaderFlip?: boolean } = {}) {
  const typed: { sel: string; value: string }[] = [];
  let consents = 0, fetches = 0, slept = 0, loader = "L1";
  const send: Send = (async () => ({ result: {} })) as Send;
  const d: Deps = {
    resolveCredential: async () => ({ cred: { origin: ORIGIN, username: "agent", getSecret: () => "pw" }, backend: "keychain" }),
    resolveSecret: async () => null,
    resolveTarget: async () => ({ wsUrl: "ws://stub", url: ORIGIN }),
    withConn: async (_ws, fn) => fn(send),
    getOrigin: async () => opts.origin ?? ORIGIN,
    getLoaderId: async () => loader,
    confirmInjection: async () => { throw new Error("password dialog must not be used for codes"); },
    confirmSecret: async () => false,
    detectLoginFields: async () => ({}),
    typeIntoField: async (_s, sel, value) => { typed.push({ sel, value }); },
    probeFields: async (_s, attr, token) => opts.fields === false ? [] : [
      { sel: `[${attr}="${token}-0"]`, type: "text", name: "otp", id: "", placeholder: "", label: "", autocomplete: "one-time-code", focused: false },
    ],
    inspectField: async () => ({ type: "text", visible: true }),
    totpCode: () => "000000",
    keychainHasTotp: () => false,
    keychainTotpSeed: () => null,
  };
  let t = NOW;
  const src: CodeSource = {
    kind: "sms",
    fetchSince: async () => {
      fetches++;
      if (opts.srcErr) throw new CdpError(opts.srcErr, "fixed");
      return typeof opts.msgs === "function" ? opts.msgs() : (opts.msgs ?? [{ at: NOW, sender: SENDER, body: BODY }]);
    },
  };
  const c: CodeDeps = {
    sms: () => src, email: () => ({ ...src, kind: "email" }),
    sleep: async (ms) => { slept += ms; t += ms; },
    now: () => t,
    confirm: async () => { consents++; if (opts.loaderFlip) loader = "L2"; return opts.allow ?? true; },
  };
  return { d, c, typed, get consents() { return consents; }, get fetches() { return fetches; }, get slept() { return slept; } };
}

const ARGS = { tabId: "T", domain: "example.com" };
const noLeak = (r: unknown) => {
  const j = JSON.stringify(r);
  expect(j).not.toContain(CODE);
  expect(j).not.toContain(SENDER);
  expect(j).not.toContain("verification code is");
};

test("sms: fills the code, returns only {filled}", async () => {
  const m = mk();
  const r = await fillSmsCode(ARGS, m.d, m.c);
  expect(r).toEqual({ filled: true });
  noLeak(r);
  expect(m.typed).toEqual([{ sel: expect.stringContaining("data-apinj-otp"), value: CODE }]);
  expect(m.consents).toBe(1);
});

test("email: same flow through the email source", async () => {
  const m = mk();
  const r = await fillEmailCode(ARGS, m.d, m.c);
  expect(r).toEqual({ filled: true });
  expect(m.typed[0].value).toBe(CODE);
});

test("origin mismatch refuses before consent and before reading any message", async () => {
  const m = mk({ origin: "https://evil.example.net" });
  const r = await fillSmsCode(ARGS, m.d, m.c);
  expect(r).toEqual({ filled: false, reason: "origin_mismatch" });
  expect(m.consents).toBe(0);
  expect(m.fetches).toBe(0);
  expect(m.typed).toHaveLength(0);
});

test("consent denied refuses before reading any message", async () => {
  const m = mk({ allow: false });
  const r = await fillSmsCode(ARGS, m.d, m.c);
  expect(r).toEqual({ filled: false, reason: "user_denied" });
  expect(m.fetches).toBe(0);
});

test("navigation during consent aborts with no keystroke", async () => {
  const m = mk({ loaderFlip: true });
  const r = await fillSmsCode(ARGS, m.d, m.c);
  expect(r).toEqual({ filled: false, reason: "navigated_during_consent" });
  expect(m.typed).toHaveLength(0);
});

test("no code before the deadline: no_code, bounded wait, nothing typed", async () => {
  const m = mk({ msgs: [] });
  const r = await fillSmsCode({ ...ARGS, timeoutMs: 6000 }, m.d, m.c);
  expect(r).toEqual({ filled: false, reason: "no_code" });
  expect(m.slept).toBe(6000);
  expect(m.typed).toHaveLength(0);
});

test("waits for a code that arrives on a later poll", async () => {
  let n = 0;
  const m = mk({ msgs: () => (++n < 3 ? [] : [{ at: NOW + 4000, sender: SENDER, body: BODY }]) });
  const r = await fillSmsCode(ARGS, m.d, m.c);
  expect(r).toEqual({ filled: true });
  expect(n).toBe(3);
});

test("timeoutMs is capped at 25 s", async () => {
  const m = mk({ msgs: [] });
  await fillSmsCode({ ...ARGS, timeoutMs: 10 * 60_000 }, m.d, m.c);
  expect(m.slept).toBe(25_000);
});

test("a message older than since is ignored", async () => {
  const m = mk({ msgs: [{ at: NOW - 5000, sender: SENDER, body: BODY }] });
  const r = await fillSmsCode({ ...ARGS, since: NOW - 1000, timeoutMs: 0 }, m.d, m.c);
  expect(r).toEqual({ filled: false, reason: "no_code" });
});

test("a WebOTP line for another host is skipped", async () => {
  const m = mk({ msgs: [{ at: NOW, sender: SENDER, body: `Your code is ${CODE}\n\n@evil.example.net #${CODE}` }] });
  const r = await fillSmsCode({ ...ARGS, timeoutMs: 0 }, m.d, m.c);
  expect(r).toEqual({ filled: false, reason: "no_code" });
  expect(m.typed).toHaveLength(0);
});

test("a number with no code keyword is never taken", async () => {
  const m = mk({ msgs: [{ at: NOW, sender: SENDER, body: "Your order 4471920 has shipped" }] });
  expect(await fillSmsCode({ ...ARGS, timeoutMs: 0 }, m.d, m.c)).toEqual({ filled: false, reason: "no_code" });
});

test("source faults map to fixed reasons", async () => {
  for (const code of ["messages_access_denied", "email_source_unavailable", "email_source_error"]) {
    const m = mk({ srcErr: code });
    expect(await fillSmsCode(ARGS, m.d, m.c)).toEqual({ filled: false, reason: code });
  }
  const m = mk({ srcErr: "something_else" });
  expect(await fillSmsCode(ARGS, m.d, m.c)).toEqual({ filled: false, reason: "source_error" });
});

test("no one-time-code field: no_otp_field, nothing typed, nothing leaked", async () => {
  const m = mk({ fields: false });
  const r = await fillSmsCode(ARGS, m.d, m.c);
  expect(r).toEqual({ filled: false, reason: "no_otp_field" });
  noLeak(r);
});

test("bad domain and missing tab are refused before anything", async () => {
  const m = mk();
  expect(await fillSmsCode({ tabId: "T", domain: "com" }, m.d, m.c)).toEqual({ filled: false, reason: "bad_domain" });
  expect(await fillSmsCode({ domain: "example.com" }, m.d, m.c)).toEqual({ filled: false, reason: "tab_unavailable" });
  expect(m.fetches).toBe(0);
});

test("resolveSince clamps to the lookback window", () => {
  expect(resolveSince(undefined, NOW)).toBe(NOW - 60_000);
  expect(resolveSince(0, NOW)).toBe(NOW - CODE_LOOKBACK_MAX_MS);
  expect(resolveSince(NOW + 99_999, NOW)).toBe(NOW);
  expect(resolveSince(new Date(NOW - 5000).toISOString(), NOW)).toBe(NOW - 5000);
  expect(resolveSince("garbage", NOW)).toBe(NOW - 60_000);
});

test("manifest: both code tools registered, strict", () => {
  for (const n of ["fill_sms_code", "fill_email_code"]) {
    const t = MANIFEST.find((x) => x.name === n)!;
    expect(t).toBeDefined();
    expect((t.inputSchema as any).additionalProperties).toBe(false);
    expect((t.inputSchema as any).required).toEqual(["tabId", "domain"]);
  }
});

// ── End to end over a fixture chat.db (synthetic rows, built in a tmp dir) ───

const dir = mkdtempSync(join(tmpdir(), "apinj-codes-e2e-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

test("e2e: fixture chat.db, newest code after since wins, older and outgoing rows ignored", async () => {
  const p = join(dir, "chat.db");
  const db = new Database(p);
  db.run("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT)");
  db.run("CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT, attributedBody BLOB, date INTEGER, is_from_me INTEGER, handle_id INTEGER)");
  db.run("INSERT INTO handle VALUES (1, ?)", [SENDER]);
  const ns = (ms: number) => (ms - 978307200 * 1000) * 1e6;
  const ins = db.prepare("INSERT INTO message (text, attributedBody, date, is_from_me, handle_id) VALUES (?,?,?,?,?)");
  const real = Date.now();
  ins.run("Your verification code is 111111", null, ns(real - 5 * 60_000), 0, 1); // before since
  ins.run("Your verification code is 222222", null, ns(real - 20_000), 0, 1);
  ins.run(`Example: your verification code is ${CODE}`, null, ns(real - 10_000), 0, 1); // newest incoming
  ins.run("my code is 999999", null, ns(real - 1_000), 1, 1); // outgoing
  db.close();

  const m = mk();
  const c: CodeDeps = { ...m.c, sms: () => messagesSource({ dbPath: p }), now: () => Date.now() };
  const r = await fillSmsCode({ ...ARGS, since: real - 60_000, timeoutMs: 0 }, m.d, c);
  expect(r).toEqual({ filled: true });
  expect(m.typed[0].value).toBe(CODE);
  noLeak(r);

  const denied = await fillSmsCode({ ...ARGS, timeoutMs: 0 }, m.d, { ...c, sms: () => messagesSource({ dbPath: join(dir, "missing", "chat.db") }) });
  expect(denied).toEqual({ filled: false, reason: "messages_access_denied" });
});

test("issue #1: a slow Allow shortens the code wait so the call stays inside the budget", async () => {
  const m = mk({ msgs: [] });
  const base = m.c.now;
  let skew = 0;
  m.c.now = () => base() + skew;
  // The human takes 20 s to click Allow; the budget is max(timeoutMs, 25 s consent timeout).
  m.c.confirm = async () => { skew += 20_000; return true; };
  const r = await fillSmsCode({ ...ARGS, timeoutMs: 20_000 }, m.d, m.c);
  expect(r).toEqual({ filled: false, reason: "no_code" });
  expect(m.slept).toBe(5_000); // 25 s budget - 20 s in the dialog, not a fresh 20 s
});
