import { expect, test } from "bun:test";
import {
  MANIFEST, OTP_ATTR, TOOLS, chooseOtpField, chooseUsernameField, fillCredential, fillTotp,
  isValidDomain, listCredentials, login, probeExpr, type Deps, type FieldInfo,
} from "../src/tools.ts";
import { CdpError, type Send } from "../src/cdp.ts";

const PASSWORD = "hunter2-super-secret";
const SEED = "JBSWY3DPEHPK3PXP";

/** A minimal page: the inputs a probe would see, in DOM order. */
type Input = Partial<FieldInfo> & { tag: string };
const inp = (tag: string, over: Partial<FieldInfo> = {}): Input => ({ tag, ...over });

interface Spy {
  consentCalls: number; typed: { sel: string; value: string }[]; evaluated: string[]; tokens: string[];
  originReads: number; loaderReads: number;
}

/**
 * `live` models a tab that can CHANGE under us: each getter is re-invoked on
 * every read, so a test can flip the origin or the loaderId at an exact moment
 * (during the consent dialog, or between two keystrokes) the way a real
 * navigation would.
 */
type Live = { origin?: () => string; loader?: () => string };

function mkDeps(over: Partial<Deps> & { origin?: string; page?: Input[]; live?: Live } = {}): { d: Deps; spy: Spy } {
  const spy: Spy = { consentCalls: 0, typed: [], evaluated: [], tokens: [], originReads: 0, loaderReads: 0 };
  const origin = over.origin ?? "https://x.com";
  const page = over.page ?? [inp("otp", { name: "otpCode" })];

  const send: Send = (async (method: string, params: any) => {
    if (method === "Runtime.evaluate") {
      spy.evaluated.push(params.expression);
      if (/input\[type=password\]/.test(params.expression)) return { result: { value: true } };
      return { result: {} };
    }
    return { result: {} };
  }) as Send;

  const d: Deps = {
    resolveCredential: async () => ({
      cred: { origin: "https://x.com", username: "alice", getSecret: () => PASSWORD },
      backend: "arc",
    }),
    resolveSecret: async () => ({ origin: "https://x.com", flags: {}, getSecret: () => PASSWORD }),
    resolveTarget: async () => ({ wsUrl: "ws://stub", url: "https://x.com/login" }),
    withConn: async (_ws, fn) => fn(send),
    getOrigin: async () => { spy.originReads++; return over.live?.origin ? over.live.origin() : origin; },
    getLoaderId: async () => { spy.loaderReads++; return over.live?.loader ? over.live.loader() : "LOADER-1"; },
    confirmInjection: async () => { spy.consentCalls++; return true; },
    confirmSecret: async () => { spy.consentCalls++; return true; },
    detectLoginFields: async () => ({ user: "#u", pass: "#p" }),
    typeIntoField: async (_s, sel, value) => { spy.typed.push({ sel, value }); },
    // Models the real probe: stamps each candidate with a per-call unique value.
    probeFields: async (_s, attr, token) => {
      spy.tokens.push(token);
      return page.map((x, i) => ({
        sel: `[${attr}="${token}-${i}"]`, type: "text", name: "", id: "", placeholder: "",
        label: "", autocomplete: "", focused: false, ...x,
      })) as FieldInfo[];
    },
    inspectField: async () => ({ type: "password", visible: true }),
    totpCode: () => "123456",
    keychainHasTotp: () => true,
    keychainTotpSeed: () => SEED,
    ...over,
  };
  return { d, spy };
}

const ARGS = { tabId: "T1", domain: "x.com" };
const keychainCred = (origin: string) => async () =>
  ({ cred: { origin, username: "bob", getSecret: () => PASSWORD }, backend: "keychain" }) as any;

// ── INVARIANT #1: origin match precedes consent and precedes any keystroke ───

test("login on a mismatched origin returns origin_mismatch and NEVER prompts for consent", async () => {
  const { d, spy } = mkDeps({ origin: "https://evil.com" });
  expect(await login(ARGS, d)).toEqual({ filled: false, reason: "origin_mismatch" });
  expect(spy.consentCalls).toBe(0);
  expect(spy.typed).toEqual([]);
});

test("fill_credential on a mismatched origin returns origin_mismatch, no consent, no keystroke", async () => {
  const { d, spy } = mkDeps({ origin: "https://evil.com" });
  expect(await fillCredential({ ...ARGS, field: "password" }, d)).toEqual({ filled: false, reason: "origin_mismatch" });
  expect(spy.consentCalls).toBe(0);
  expect(spy.typed).toEqual([]);
});

test("fill_totp on a mismatched origin returns origin_mismatch, no consent, no keystroke", async () => {
  const { d, spy } = mkDeps({ origin: "https://evil.com" });
  expect(await fillTotp(ARGS, d)).toEqual({ filled: false, reason: "origin_mismatch" });
  expect(spy.consentCalls).toBe(0);
  expect(spy.typed).toEqual([]);
});

test("an unreadable tab origin blocks rather than falling through", async () => {
  const { d, spy } = mkDeps({ origin: "" });
  expect(await login(ARGS, d)).toEqual({ filled: false, reason: "origin_mismatch" });
  expect(spy.consentCalls).toBe(0);
});

// ── C1: the consent dialog is a navigation window (time-of-check/time-of-use) ─
//
// `confirmInjection` is a blocking osascript dialog with `giving up after 60`.
// The shipped code read the origin ONCE before it and never again, so anything
// that navigated the tab during those seconds — a page timer, a meta refresh, or
// the SAME prompt-injected model calling `navigate_page` through its browser MCP —
// got the password typed into its own page while the human had truthfully
// approved the bank. These tests drive the tab from inside the dialog and from
// between the two keystrokes; a passing run means nothing was typed.

test("C1: navigating the tab DURING the consent dialog aborts before any keystroke", async () => {
  const live = { origin: "https://x.com", loader: "L1" };
  const { d, spy } = mkDeps({
    live: { origin: () => live.origin, loader: () => live.loader },
    confirmInjection: async () => {
      // The model drives the tab away while the human stares at the dialog.
      live.origin = "https://evil.com";
      live.loader = "L2";
      return true; // …and the human clicks Allow on the truthful mybank prompt.
    },
  });
  expect(await login(ARGS, d)).toEqual({ filled: false, reason: "navigated_during_consent" });
  expect(spy.typed).toEqual([]); // ← the whole point: the password went nowhere
  expect(spy.originReads).toBeGreaterThan(1); // the origin was RE-read, not re-checked from a string
  expect(spy.loaderReads).toBeGreaterThan(1);
});

test("C1: a SAME-ORIGIN document swap during consent is still refused (loaderId)", async () => {
  // Re-reading the origin alone is not enough: an in-flight navigation can commit
  // to a page whose origin string is identical (or race the read). Any document
  // commit mints a new loaderId, which is the fact that actually settles it.
  const live = { loader: "L1" };
  const { d, spy } = mkDeps({
    live: { loader: () => live.loader },
    confirmInjection: async () => { live.loader = "L2"; return true; },
  });
  expect(await login(ARGS, d)).toEqual({ filled: false, reason: "navigated_during_consent" });
  expect(spy.typed).toEqual([]);
});

test("C1: navigation BETWEEN the username and the password keystroke aborts the password", async () => {
  // The guard runs before EVERY keystroke, not once after the dialog: the
  // username fill is itself a round-trip the page can navigate under.
  const live = { origin: "https://x.com", loader: "L1" };
  const typed: { sel: string; value: string }[] = [];
  const { d } = mkDeps({
    live: { origin: () => live.origin, loader: () => live.loader },
    typeIntoField: async (_s, sel, value) => {
      typed.push({ sel, value });
      if (value === "alice") { live.origin = "https://evil.com"; live.loader = "L2"; }
    },
  });
  expect(await login(ARGS, d)).toEqual({ filled: false, reason: "navigated_during_consent" });
  expect(typed.map((t) => t.value)).toEqual(["alice"]); // username only
  expect(typed.some((t) => t.value === PASSWORD)).toBe(false);
});

test("C1: fill_credential(password) re-checks after consent too", async () => {
  const live = { origin: "https://x.com", loader: "L1" };
  const { d, spy } = mkDeps({
    live: { origin: () => live.origin, loader: () => live.loader },
    confirmInjection: async () => { live.origin = "https://evil.com"; live.loader = "L2"; return true; },
  });
  expect(await fillCredential({ ...ARGS, field: "password" }, d))
    .toEqual({ filled: false, reason: "navigated_during_consent" });
  expect(spy.typed).toEqual([]);
});

test("C1: fill_totp re-checks after consent too — the live code is not typed elsewhere", async () => {
  const live = { origin: "https://x.com", loader: "L1" };
  const { d, spy } = mkDeps({
    live: { origin: () => live.origin, loader: () => live.loader },
    confirmInjection: async () => { live.origin = "https://evil.com"; live.loader = "L2"; return true; },
  });
  expect(await fillTotp(ARGS, d)).toEqual({ filled: false, reason: "navigated_during_consent" });
  expect(spy.typed).toEqual([]);
});

test("C1: a tab that does NOT move still fills, and the guard really ran", async () => {
  // Guards against the trivially-safe mutation of this fix (always abort).
  const { d, spy } = mkDeps();
  expect(await login(ARGS, d)).toEqual({ filled: true, submitted: false });
  expect(spy.typed.map((t) => t.value)).toEqual(["alice", PASSWORD]);
  // 1 capture + 1 post-consent + 1 per keystroke.
  expect(spy.originReads).toBeGreaterThanOrEqual(4);
  expect(spy.loaderReads).toBeGreaterThanOrEqual(4);
});

test("C1: an unverifiable loaderId fails closed, before the dialog", async () => {
  const { d, spy } = mkDeps({ getLoaderId: async () => "" });
  expect(await login(ARGS, d)).toEqual({ filled: false, reason: "tab_unavailable" });
  expect(spy.consentCalls).toBe(0);
  expect(spy.typed).toEqual([]);
});

test("C1: a tab that dies during the dialog aborts rather than typing", async () => {
  let dead = false;
  const { d, spy } = mkDeps({
    live: { origin: () => { if (dead) throw new CdpError("cdp_error", "detached"); return "https://x.com"; } },
    confirmInjection: async () => { dead = true; return true; },
  });
  expect(await login(ARGS, d)).toEqual({ filled: false, reason: "tab_unavailable" });
  expect(spy.typed).toEqual([]);
});

// ── M3: the guard reaches INSIDE typeIntoField, to the keystroke itself ──────
//
// The outer `await guard()` before each `typeIntoField` still leaves three CDP
// round-trips before `Input.insertText`. `inject.ts` re-asserts the guard as the
// last act before the keystroke; these tests prove the tools actually HAND it
// that guard — a correct inject.ts wired to `undefined` is the same hole.

/** Every keystroke path, with the value each is expected to type. */
const KEYSTROKE_PATHS: { name: string; call: (d: Deps) => Promise<unknown> }[] = [
  { name: "login(username+password)", call: (d) => login(ARGS, d) },
  { name: "fill_credential(username)", call: (d) => fillCredential({ ...ARGS, field: "username" }, d) },
  { name: "fill_credential(password)", call: (d) => fillCredential({ ...ARGS, field: "password" }, d) },
  { name: "fill_totp", call: (d) => fillTotp(ARGS, d) },
];

test("M3: every typeIntoField call site is handed the real guard, not undefined", async () => {
  for (const p of KEYSTROKE_PATHS) {
    const handed: unknown[] = [];
    const { d } = mkDeps({
      typeIntoField: async (_s, _sel, _v, guard) => { handed.push(guard); },
    });
    await p.call(d);
    expect(handed.length).toBeGreaterThan(0);
    for (const g of handed) expect(typeof g).toBe("function");
  }
});

test("M3: a navigation inside typeIntoField aborts that keystroke on EVERY path", async () => {
  // The stub plays the real inject.ts: it resolves/focuses/verifies (during which
  // the tab commits a new document), then calls the guard it was given. A path
  // that passed no guard, or a guard that re-checked a cached string, types here.
  for (const p of KEYSTROKE_PATHS) {
    const live = { origin: "https://x.com", loader: "L1" };
    const typed: string[] = [];
    const { d } = mkDeps({
      live: { origin: () => live.origin, loader: () => live.loader },
      typeIntoField: async (_s, _sel, value, guard) => {
        live.origin = "https://evil.com"; live.loader = "L2"; // commits between verify and insert
        await guard!();                                       // ← inject.ts's last act
        typed.push(value);                                    // only reached if the guard passed
      },
    });
    expect(await p.call(d)).toEqual(
      expect.objectContaining({ filled: false, reason: "navigated_during_consent" }));
    expect(typed).toEqual([]);
  }
});

test("M3: the inner guard is not vacuous — a still tab fills normally", async () => {
  // Mutation witness for the test above: same stub, tab does NOT move.
  for (const p of KEYSTROKE_PATHS) {
    const typed: string[] = [];
    const { d } = mkDeps({
      typeIntoField: async (_s, _sel, value, guard) => { await guard!(); typed.push(value); },
    });
    expect(await p.call(d)).toEqual(expect.objectContaining({ filled: true }));
    expect(typed.length).toBeGreaterThan(0);
  }
});

// ── Minor: the submit click is a gated action too ────────────────────────────

test("submit: a navigation after the password fill means NO submit click", async () => {
  const live = { origin: "https://x.com", loader: "L1" };
  const spy0: { sel: string; value: string }[] = [];
  const { d, spy } = mkDeps({
    live: { origin: () => live.origin, loader: () => live.loader },
    typeIntoField: async (_s, sel, value) => {
      spy0.push({ sel, value });
      if (value === PASSWORD) { live.origin = "https://evil.com"; live.loader = "L2"; }
    },
  });
  expect(await login({ ...ARGS, submit: true }, d))
    .toEqual({ filled: false, reason: "navigated_during_consent" });
  // The password did land (on the authorised page); the CLICK did not follow it.
  expect(spy0.map((t) => t.value)).toEqual(["alice", PASSWORD]);
  expect(spy.evaluated.some((e) => /input\[type=password\]/.test(e))).toBe(false);
});

test("submit: a still tab DOES submit — the guard above is not vacuous", async () => {
  const { d, spy } = mkDeps();
  expect(await login({ ...ARGS, submit: true }, d)).toEqual({ filled: true, submitted: true });
  expect(spy.evaluated.some((e) => /input\[type=password\]/.test(e))).toBe(true);
});

// ── I3 (entry point): `domain` must be a registrable domain, not a suffix ────
//
// `list_credentials` has no consent dialog and no origin gate — correctly, since
// it is metadata-only — which makes it the cheapest sweep surface in the server.
// With a loose suffix match downstream, `{domain:"com"}` returned a real saved
// origin + username, so a prompt-injected model could enumerate which banks the
// user uses and under what names. No password leaks; the metadata is the payload.

test("I3: list_credentials({domain:'com'}) is bad_domain and surfaces NOTHING", async () => {
  const { d } = mkDeps();
  for (const bare of ["com", "net", "org", "uk", "io", "co.uk", "com.au", "github.io"]) {
    const r = await listCredentials({ domain: bare }, d);
    expect(r).toEqual({ credentials: [], reason: "bad_domain" });
    expect(JSON.stringify(r)).not.toContain("alice");
    expect(JSON.stringify(r)).not.toContain("https://x.com");
  }
});

test("I3: the sweep is refused BEFORE the vault is even consulted", async () => {
  let looked = 0;
  const { d } = mkDeps({ resolveCredential: async () => { looked++; throw new Error("must not run"); } });
  expect(await listCredentials({ domain: "com" }, d)).toEqual({ credentials: [], reason: "bad_domain" });
  expect(looked).toBe(0);
});

test("I3: the tab tools reject a bare-TLD domain with bad_domain, no consent, no keystroke", async () => {
  for (const call of [
    (d: Deps) => login({ tabId: "T1", domain: "com" }, d),
    (d: Deps) => fillCredential({ tabId: "T1", domain: "com", field: "password" }, d),
    (d: Deps) => fillTotp({ tabId: "T1", domain: "co.uk" }, d),
  ]) {
    const { d, spy } = mkDeps();
    expect(await call(d)).toEqual({ filled: false, reason: "bad_domain" });
    expect(spy.consentCalls).toBe(0);
    expect(spy.typed).toEqual([]);
  }
});

test("I3: junk that is not a domain at all is bad_domain", async () => {
  const { d } = mkDeps();
  for (const junk of [
    "*", ".", "..", ".com", "com.", "x..y", "https://mybank.com", "mybank.com/login",
    "mybank.com:443", "user@mybank.com", "my bank.com", "-bank.com", "bank-.com",
    "mybank.c", "mybank.123", "localhost",
  ]) {
    expect(await listCredentials({ domain: junk }, d)).toEqual({ credentials: [], reason: "bad_domain" });
  }
});

test("I3: real registrable domains still work", async () => {
  const { d } = mkDeps();
  for (const good of ["x.com", "mybank.com", "auth.mybank.co.uk", "my-bank.io", "xn--mybnk-l11b.com", "a.b.c.example.org"]) {
    const r = await listCredentials({ domain: good }, d);
    expect(r.reason).toBeUndefined();
    expect(r.credentials).toHaveLength(1);
  }
});

test("isValidDomain is the shared rule, exported for the tab tools and the listing alike", () => {
  expect(isValidDomain("mybank.com")).toBe(true);
  expect(isValidDomain("MyBank.COM")).toBe(true); // case is not the caller's problem
  expect(isValidDomain("com")).toBe(false);
  expect(isValidDomain("co.uk")).toBe(false);
  expect(isValidDomain("")).toBe(false);
  expect(isValidDomain("a".repeat(64) + ".com")).toBe(false); // label cap
});

// ── Reason vocabulary: a MISSING argument is never `not_found` ───────────────

test("R3-6: a missing domain is domain_required on EVERY tool, never not_found", async () => {
  const { d } = mkDeps();
  expect(await listCredentials({}, d)).toEqual({ credentials: [], reason: "domain_required" });
  for (const call of [
    (dd: Deps) => login({ tabId: "T1" }, dd),
    (dd: Deps) => fillCredential({ tabId: "T1", field: "password" }, dd),
    (dd: Deps) => fillTotp({ tabId: "T1" }, dd),
  ]) {
    const r = await call(d);
    expect(r).toEqual({ filled: false, reason: "domain_required" });
    expect(r.reason).not.toBe("not_found"); // `not_found` reads as "bad credential"
  }
});

// ── I5 (tools half): the ambiguous-password refusal surfaces its own reason ──

test("I5: two visible password inputs refuse with ambiguous_password_field, typing nothing", async () => {
  for (const call of [
    (d: Deps) => login(ARGS, d),
    (d: Deps) => fillCredential({ ...ARGS, field: "password" }, d),
  ]) {
    const { d, spy } = mkDeps({ detectLoginFields: async () => ({ ambiguous: true }) });
    const r = await call(d);
    expect(r).toEqual({ filled: false, reason: "ambiguous_password_field" });
    expect(r.reason).not.toBe("no_password_field"); // "which one?" is not "there is none"
    expect(spy.typed).toEqual([]);
  }
});

// ── FIX 5: Keychain origin binding — bind to the STORED origin, fail closed ──

test("FIX5: keychain cred bound to auth.mybank.com does NOT fill on evil.com", async () => {
  // The attack: caller names a domain it controls but a credential it does not own.
  const { d, spy } = mkDeps({
    resolveCredential: keychainCred("https://auth.mybank.com"),
    origin: "https://evil.com",
  });
  expect(await login({ tabId: "T1", domain: "evil.com", name: "mybank" }, d))
    .toEqual({ filled: false, reason: "origin_mismatch" });
  expect(spy.consentCalls).toBe(0);
  expect(spy.typed).toEqual([]);
});

test("FIX5: keychain cred whose stored origin matches the tab passes the gate", async () => {
  const { d, spy } = mkDeps({
    resolveCredential: keychainCred("https://auth.mybank.com"),
    origin: "https://auth.mybank.com",
  });
  expect(await login({ tabId: "T1", domain: "mybank.com", name: "mybank" }, d))
    .toEqual({ filled: true, submitted: false });
  expect(spy.typed.map((t) => t.value)).toEqual(["bob", PASSWORD]);
});

test("FIX5: keychain cred with NO stored origin fails closed, never prompting", async () => {
  const { d, spy } = mkDeps({ resolveCredential: keychainCred(""), origin: "https://x.com" });
  expect(await login(ARGS, d)).toEqual({ filled: false, reason: "no_origin_binding" });
  expect(spy.consentCalls).toBe(0);
  expect(spy.typed).toEqual([]);
});

test("FIX5: the unbound-credential refusal covers every tab tool", async () => {
  for (const call of [
    (d: Deps) => login(ARGS, d),
    (d: Deps) => fillCredential({ ...ARGS, field: "password" }, d),
    (d: Deps) => fillTotp(ARGS, d),
  ]) {
    const { d, spy } = mkDeps({ resolveCredential: keychainCred("") });
    expect(await call(d)).toEqual({ filled: false, reason: "no_origin_binding" });
    expect(spy.consentCalls).toBe(0);
  }
});

test("FIX5: the caller-supplied domain is never used as the binding", async () => {
  // Same cred, same tab; only the caller's `domain` differs. If domain were the
  // binding, naming the tab's own host would pass. It must not.
  const { d } = mkDeps({ resolveCredential: keychainCred(""), origin: "https://x.com" });
  expect(await login({ tabId: "T1", domain: "x.com" }, d)).toEqual({ filled: false, reason: "no_origin_binding" });
});

// ── FIX 3: a vault FAULT is not a vault MISS ────────────────────────────────

test("FIX3: a locked keychain at lookup time is vault_locked, never not_found", async () => {
  const { d } = mkDeps({ resolveCredential: async () => { throw new CdpError("vault_locked", "keychain access failed"); } });
  expect(await login(ARGS, d)).toEqual({ filled: false, reason: "vault_locked" });
});

test("FIX3: an Arc SQLITE_BUSY at lookup time is vault_error, never not_found", async () => {
  const { d } = mkDeps({ resolveCredential: async () => { throw new Error("SQLITE_BUSY: database is locked"); } });
  const r = await login(ARGS, d);
  expect(r).toEqual({ filled: false, reason: "vault_error" });
  expect(r.reason).not.toBe("not_found");
});

test("FIX3: a readable vault with no entry is still not_found", async () => {
  const { d } = mkDeps({ resolveCredential: async () => ({ found: false, tried: ["arc", "keychain"] }) });
  expect(await login(ARGS, d)).toEqual({ filled: false, reason: "not_found" });
});

test("FIX3: a vault fault never leaks its message", async () => {
  const { d } = mkDeps({ resolveCredential: async () => { throw new Error(`boom ${PASSWORD}`); } });
  expect(JSON.stringify(await login(ARGS, d))).not.toContain(PASSWORD);
});

test("FIX3: list_credentials surfaces a vault fault instead of an empty list", async () => {
  const { d } = mkDeps({ resolveCredential: async () => { throw new CdpError("vault_locked", "x"); } });
  expect(await listCredentials({ domain: "x.com" }, d)).toEqual({ credentials: [], reason: "vault_locked" });
});

// ── FIX 4: identifier-first pages ───────────────────────────────────────────

test("FIX4: fill_credential(username) works on a page with NO password field", async () => {
  // detectLoginFields anchors on the password input, so it returns {} here —
  // the Google/Microsoft identifier-first case.
  const { d, spy } = mkDeps({
    detectLoginFields: async () => ({}),
    page: [inp("email", { name: "identifier", type: "email" })],
  });
  expect(await fillCredential({ ...ARGS, field: "username" }, d)).toEqual({ filled: true });
  expect(spy.typed).toHaveLength(1);
  expect(spy.typed[0].value).toBe("alice");
});

test("FIX4: a password request on an identifier-first page is still no_password_field", async () => {
  const { d } = mkDeps({ detectLoginFields: async () => ({}) });
  expect(await fillCredential({ ...ARGS, field: "password" }, d)).toEqual({ filled: false, reason: "no_password_field" });
});

test("FIX4: a username request with no username field anywhere is no_username_field", async () => {
  const { d } = mkDeps({ detectLoginFields: async () => ({}), page: [] });
  expect(await fillCredential({ ...ARGS, field: "username" }, d)).toEqual({ filled: false, reason: "no_username_field" });
});

test("FIX4: a normal login page still uses the detected username field directly", async () => {
  const { d, spy } = mkDeps();
  expect(await fillCredential({ ...ARGS, field: "username" }, d)).toEqual({ filled: true });
  expect(spy.typed).toEqual([{ sel: "#u", value: "alice" }]);
  expect(spy.tokens).toEqual([]); // no probe needed
});

// ── FIX 1: the OTP stamp must be unique per call ────────────────────────────

// A stale stamp is a property of a PERSISTENT DOM across two calls, so a stubbed
// probe cannot reproduce it. These tests execute the real serialized expression
// against a minimal document shim, and resolve selectors the way a browser does:
// first match in document order wins.
class El {
  attrs: Record<string, string> = {};
  constructor(public p: { name?: string; id?: string; type?: string; ac?: string; visible?: boolean }) {}
  get type() { return this.p.type ?? "text"; }
  get name() { return this.p.name ?? ""; }
  get id() { return this.p.id ?? ""; }
  get placeholder() { return ""; }
  get autocomplete() { return this.p.ac ?? ""; }
  get offsetParent() { return this.p.visible === false ? null : {}; }
  setAttribute(k: string, v: string) { this.attrs[k] = v; }
  removeAttribute(k: string) { delete this.attrs[k]; }
  getAttribute(k: string) { return this.attrs[k] ?? null; }
}
class Doc {
  activeElement: El | null = null;
  constructor(public els: El[]) {}
  querySelectorAll(sel: string): El[] {
    if (sel === "input") return this.els;
    const m = sel.match(/^\[([\w-]+)\]$/);
    if (m) return this.els.filter((e) => e.attrs[m[1]] !== undefined);
    throw new Error(`unsupported selector ${sel}`);
  }
  /** Browser semantics: FIRST element in document order that matches. */
  querySelector(sel: string): El | null {
    const m = sel.match(/^\[([\w-]+)="([^"]+)"\]$/);
    return m ? this.els.find((e) => e.attrs[m[1]] === m[2]) ?? null : null;
  }
}
const runExpr = (expr: string, doc: Doc) => new Function("document", `return ${expr}`)(doc);

// The pre-fix expression, kept verbatim as a regression witness: it stamps only
// the chosen element, with a SHARED literal value, and never clears.
const staleExpr = (attr: string) =>
  `(()=>{const els=[...document.querySelectorAll('input')].filter(e=>!!e.offsetParent&&e.type!=='password'&&e.type!=='hidden');` +
  `const stamp=e=>{e.setAttribute('${attr}','1');return '[${attr}="1"]'};` +
  `let e=els.find(x=>/otp|totp/i.test((x.name||'')));return e?stamp(e):null})()`;

test("FIX1: two sequential probes on ONE dom each resolve to their own field", () => {
  // Step 1 shows the emailed-code box; step 2 replaces it with the authenticator box.
  const a = new El({ name: "otpCode" });
  const b = new El({ name: "totp", visible: false });
  const doc = new Doc([a, b]);

  const sel1 = chooseOtpField(runExpr(probeExpr(OTP_ATTR, "otp1"), doc));
  expect(doc.querySelector(sel1!)).toBe(a);

  a.p.visible = false; b.p.visible = true; // the page advances

  const sel2 = chooseOtpField(runExpr(probeExpr(OTP_ATTR, "otp2"), doc));
  expect(sel2).not.toBe(sel1);
  expect(doc.querySelector(sel2!)).toBe(b); // NOT the stale first element
  // Exactly one element carries the stamp — the probe cleared the previous one.
  expect(doc.els.filter((e) => e.attrs[OTP_ATTR] !== undefined)).toEqual([b]);
});

test("FIX1: the old shared-literal stamp DID mis-resolve to the stale field", () => {
  // Proves the bug was real and that the shim reproduces it, so the test above
  // is discriminating rather than vacuously green.
  const a = new El({ name: "otpCode" });
  const b = new El({ name: "totp", visible: false });
  const doc = new Doc([a, b]);

  const sel1 = runExpr(staleExpr(OTP_ATTR), doc);
  expect(doc.querySelector(sel1)).toBe(a);

  a.p.visible = false; b.p.visible = true;

  const sel2 = runExpr(staleExpr(OTP_ATTR), doc);
  expect(sel2).toBe(sel1);                     // same literal selector
  expect(doc.querySelector(sel2)).toBe(a);     // ← resolves to the WRONG field
});

test("FIX1: two sequential fill_totp calls type into different selectors", async () => {
  const { d: dA, spy: spyA } = mkDeps({ page: [inp("a", { name: "otpCode" })] });
  const { d: dB, spy: spyB } = mkDeps({ page: [inp("b", { name: "zip" }), inp("c", { name: "totp" })] });
  expect(await fillTotp(ARGS, dA)).toEqual({ filled: true });
  expect(await fillTotp(ARGS, dB)).toEqual({ filled: true });
  expect(spyA.typed[0].sel).not.toBe(spyB.typed[0].sel);
  expect(spyB.typed[0].sel).toContain(`${spyB.tokens[0]}-1`); // the totp box, not zip
});

test("FIX1: every probe issues a fresh token", async () => {
  const { d, spy } = mkDeps();
  await fillTotp(ARGS, d);
  await fillTotp(ARGS, d);
  expect(spy.tokens).toHaveLength(2);
  expect(spy.tokens[0]).not.toBe(spy.tokens[1]);
});

test("FIX1: the probe strips prior stamps before re-stamping", () => {
  const e = probeExpr("data-apinj-otp", "otp7");
  expect(e).toContain("removeAttribute");
  expect(e).toContain("otp7");
});

// ── FIX 2: OTP naming heuristic must not grab benign 'code' fields ──────────

test("FIX2: a 'Zip code' input before the real OTP input is NOT chosen", () => {
  const f = [
    { sel: "#zip", type: "text", name: "zip", id: "zip", placeholder: "Zip code", label: "", autocomplete: "", focused: false },
    { sel: "#otp", type: "text", name: "otpCode", id: "otp", placeholder: "", label: "", autocomplete: "", focused: false },
  ];
  expect(chooseOtpField(f)).toBe("#otp");
});

test("FIX2: 'Promo code' alone is not an OTP field", () => {
  const f = [{ sel: "#promo", type: "text", name: "promo", id: "", placeholder: "Promo code", label: "", autocomplete: "", focused: false }];
  // Sole visible input still wins via the lone-input fallback, so add a second
  // input to isolate the NAMING rule under test.
  const two = [...f, { sel: "#other", type: "text", name: "street", id: "", placeholder: "", label: "", autocomplete: "", focused: false }];
  expect(chooseOtpField(two)).toBeNull();
});

test("FIX2: autocomplete=one-time-code beats DOM order", () => {
  const f = [
    { sel: "#zip", type: "text", name: "zip", id: "", placeholder: "Zip code", label: "", autocomplete: "", focused: false },
    { sel: "#real", type: "text", name: "x", id: "", placeholder: "", label: "", autocomplete: "one-time-code", focused: false },
  ];
  expect(chooseOtpField(f)).toBe("#real");
});

test("FIX2: genuine OTP namings are still recognised", () => {
  for (const name of ["otpCode", "totp", "mfa", "2fa_token", "one_time_password", "verification_code", "authenticator", "passcode"]) {
    const f = [
      { sel: "#a", type: "text", name: "street", id: "", placeholder: "", label: "", autocomplete: "", focused: false },
      { sel: "#b", type: "text", name, id: "", placeholder: "", label: "", autocomplete: "", focused: false },
    ];
    expect(chooseOtpField(f)).toBe("#b");
  }
});

const mkField = (over: Partial<FieldInfo>): FieldInfo =>
  ({ sel: "#s", type: "text", name: "", id: "", placeholder: "", label: "", autocomplete: "", focused: false, ...over });

test("chooseUsernameField prefers autocomplete, then naming", () => {
  expect(chooseUsernameField([mkField({ sel: "#a" }), mkField({ sel: "#b", autocomplete: "username" })])).toBe("#b");
  expect(chooseUsernameField([mkField({ sel: "#a", name: "street" }), mkField({ sel: "#b", name: "email" })])).toBe("#b");
  expect(chooseUsernameField([])).toBeNull();
});

// ── Fix round 2, item 1: the untyped fallback must not guess ────────────────

test("R2-1: an unlabelled username box after a Search box is REFUSED, not guessed", () => {
  // Identifier-first page: site search renders first, the real username box has
  // no name/id/placeholder/aria-label hint. Picking first-in-DOM-order would type
  // the username into the search field and report success.
  const f = [mkField({ sel: "#search", type: "text" }), mkField({ sel: "#user", type: "text" })];
  expect(chooseUsernameField(f)).toBeNull();
});

test("R2-1: a lone unlabelled text input is still accepted", () => {
  expect(chooseUsernameField([mkField({ sel: "#only", type: "text" })])).toBe("#only");
  expect(chooseUsernameField([mkField({ sel: "#only", type: "email" })])).toBe("#only");
});

test("R2-1: a labelled username box still wins over an earlier search box", () => {
  const f = [mkField({ sel: "#search", type: "text", placeholder: "Search" }), mkField({ sel: "#user", name: "username" })];
  expect(chooseUsernameField(f)).toBe("#user");
});

test("R2-1: non-text candidates do not count toward the lone-input rule", () => {
  // A checkbox alongside one text input must not make the text input ambiguous.
  const f = [mkField({ sel: "#agree", type: "checkbox" }), mkField({ sel: "#user", type: "text" })];
  expect(chooseUsernameField(f)).toBe("#user");
});

test("R2-1: fill_credential refuses rather than typing the username into search", async () => {
  const { d, spy } = mkDeps({
    detectLoginFields: async () => ({}),
    page: [inp("search", { type: "text" }), inp("user", { type: "text" })],
  });
  expect(await fillCredential({ ...ARGS, field: "username" }, d)).toEqual({ filled: false, reason: "no_username_field" });
  expect(spy.typed).toEqual([]);
});

// ── Fix round 2, item 3: consent is asked about the BOUND origin ────────────

test("R2-3: the consent dialog is asked about the bound origin, not the caller domain", async () => {
  const asked: { origin: string; user: string; requested: string }[] = [];
  const { d } = mkDeps({
    resolveCredential: keychainCred("https://auth.mybank.com"),
    origin: "https://auth.mybank.com",
    confirmInjection: async (origin, user, requested) => { asked.push({ origin, user, requested }); return true; },
  });
  await login({ tabId: "T1", domain: "mybank.com", name: "mybank" }, d);
  expect(asked).toEqual([{ origin: "https://auth.mybank.com", user: "bob", requested: "mybank.com" }]);
});

test("R2-3: the origin passed to consent is the one the gate enforces", async () => {
  // Whatever the human authorised must be the value compared against the tab —
  // if these could diverge, the dialog would be authorising a different site.
  let asked = "";
  const { d } = mkDeps({
    resolveCredential: keychainCred("https://auth.mybank.com"),
    origin: "https://auth.mybank.com",
    confirmInjection: async (origin) => { asked = origin; return true; },
  });
  expect(await login({ tabId: "T1", domain: "anything-else.com" }, d)).toEqual({ filled: true, submitted: false });
  expect(asked).toBe("https://auth.mybank.com");
});

// ── INVARIANT: user denial blocks every keystroke ────────────────────────────

test("a denied consent dialog blocks the fill", async () => {
  const { d, spy } = mkDeps({ confirmInjection: async () => false });
  expect(await login(ARGS, d)).toEqual({ filled: false, reason: "user_denied" });
  expect(spy.typed).toEqual([]);
});

test("login raises exactly ONE consent dialog for both fields", async () => {
  const { d, spy } = mkDeps();
  expect(await login(ARGS, d)).toEqual({ filled: true, submitted: false });
  expect(spy.consentCalls).toBe(1);
  expect(spy.typed.map((t) => t.sel)).toEqual(["#u", "#p"]);
});

// ── INVARIANT #2: no secret crosses a tool boundary ──────────────────────────

test("no tool return value contains the password or the seed", async () => {
  const { d } = mkDeps();
  const outs = [
    await login({ ...ARGS, submit: true }, d),
    await fillCredential({ ...ARGS, field: "password" }, d),
    await fillTotp(ARGS, d),
    await listCredentials(ARGS, d),
  ];
  const blob = JSON.stringify(outs);
  expect(blob).not.toContain(PASSWORD);
  expect(blob).not.toContain(SEED);
  expect(blob).not.toContain("123456"); // the generated code is not returned either
});

test("the password does reach the DOM even though it never reaches the caller", async () => {
  const { d, spy } = mkDeps();
  await fillCredential({ ...ARGS, field: "password" }, d);
  expect(spy.typed).toEqual([{ sel: "#p", value: PASSWORD }]);
});

test("a decrypt error message never leaks into the reason", async () => {
  const { d } = mkDeps({
    resolveCredential: async () => ({
      cred: { origin: "https://x.com", username: "alice", getSecret: () => { throw new CdpError("decrypt_failed", `CBC on ${PASSWORD}`); } },
      backend: "arc",
    }),
  });
  const r = await login(ARGS, d);
  expect(r).toEqual({ filled: false, reason: "decrypt_failed" });
  expect(JSON.stringify(r)).not.toContain(PASSWORD);
});

// ── INVARIANT #3: distinct failure shapes ────────────────────────────────────

test("a locked vault at decrypt time is distinct from a wrong credential", async () => {
  const { d } = mkDeps({
    resolveCredential: async () => ({
      cred: { origin: "https://x.com", username: "alice", getSecret: () => { throw new CdpError("vault_locked", "keychain"); } },
      backend: "arc",
    }),
  });
  expect(await login(ARGS, d)).toEqual({ filled: false, reason: "vault_locked" });
});

test("every failure reason is distinct from every other", async () => {
  const seen = new Set<string>();
  const cases: [string, Deps][] = [
    ["not_found", mkDeps({ resolveCredential: async () => ({ found: false, tried: [] }) }).d],
    ["vault_locked", mkDeps({ resolveCredential: async () => { throw new CdpError("vault_locked", "x"); } }).d],
    ["vault_error", mkDeps({ resolveCredential: async () => { throw new Error("busy"); } }).d],
    ["no_origin_binding", mkDeps({ resolveCredential: keychainCred("") }).d],
    ["tab_unavailable", mkDeps({ resolveTarget: async () => { throw new CdpError("tab_unavailable", "x"); } }).d],
    ["origin_mismatch", mkDeps({ origin: "https://evil.com" }).d],
    ["user_denied", mkDeps({ confirmInjection: async () => false }).d],
    ["no_password_field", mkDeps({ detectLoginFields: async () => ({}) }).d],
  ];
  for (const [expected, d] of cases) {
    const r = await login(ARGS, d);
    expect(r.reason).toBe(expected);
    expect(seen.has(r.reason!)).toBe(false);
    seen.add(r.reason!);
  }
  expect(seen.size).toBe(8);
});

test("a dead tab is tab_unavailable", async () => {
  const { d, spy } = mkDeps({ resolveTarget: async () => { throw new CdpError("tab_unavailable", "gone"); } });
  expect(await login(ARGS, d)).toEqual({ filled: false, reason: "tab_unavailable" });
  expect(spy.consentCalls).toBe(0);
});

test("a credential with no TOTP seed is no_totp", async () => {
  const { d, spy } = mkDeps({ keychainTotpSeed: () => null });
  expect(await fillTotp(ARGS, d)).toEqual({ filled: false, reason: "no_totp" });
  expect(spy.typed).toEqual([]);
});

test("no OTP field on the page is no_otp_field", async () => {
  const { d } = mkDeps({ page: [inp("a", { name: "street" }), inp("b", { name: "city" })] });
  expect(await fillTotp(ARGS, d)).toEqual({ filled: false, reason: "no_otp_field" });
});

// ── INVARIANT #4: list_credentials is metadata only ─────────────────────────

test("list_credentials returns metadata only", async () => {
  const { d } = mkDeps();
  expect(await listCredentials({ domain: "x.com" }, d)).toEqual({
    credentials: [{ origin: "https://x.com", username: "alice", backend: "arc", has_totp: true }],
  });
});

test("list_credentials still lists an unbound keychain cred, showing its empty origin", async () => {
  const { d } = mkDeps({ resolveCredential: keychainCred(""), keychainHasTotp: () => false });
  expect(await listCredentials({ domain: "x.com" }, d)).toEqual({
    credentials: [{ origin: "", username: "bob", backend: "keychain", has_totp: false }],
  });
});

test("list_credentials reports the stored origin for a bound keychain cred", async () => {
  const { d } = mkDeps({ resolveCredential: keychainCred("https://auth.mybank.com"), keychainHasTotp: () => false });
  expect(await listCredentials({ domain: "mybank.com" }, d)).toEqual({
    credentials: [{ origin: "https://auth.mybank.com", username: "bob", backend: "keychain", has_totp: false }],
  });
});

// ── Behaviour ────────────────────────────────────────────────────────────────

test("fill_totp types the generated code into the detected field", async () => {
  const { d, spy } = mkDeps();
  expect(await fillTotp(ARGS, d)).toEqual({ filled: true });
  expect(spy.typed).toHaveLength(1);
  expect(spy.typed[0].value).toBe("123456");
});

test("fill_totp honours an explicit selector without probing the DOM", async () => {
  const { d, spy } = mkDeps();
  expect(await fillTotp({ ...ARGS, selector: "#otp" }, d)).toEqual({ filled: true });
  expect(spy.typed).toEqual([{ sel: "#otp", value: "123456" }]);
  expect(spy.tokens).toEqual([]);
});

test("login reports submitted from the page's own answer", async () => {
  const { d, spy } = mkDeps();
  expect(await login({ ...ARGS, submit: true }, d)).toEqual({ filled: true, submitted: true });
  expect(spy.evaluated.join(" ")).toContain("input[type=password]");
});

// ── Registration ─────────────────────────────────────────────────────────────

test("all five tools are registered with schemas", () => {
  const names = MANIFEST.map((m) => m.name).sort();
  expect(names).toEqual(["fill_credential", "fill_secret", "fill_totp", "list_credentials", "login"]);
  for (const m of MANIFEST) {
    expect(typeof TOOLS[m.name]).toBe("function");
    expect(m.inputSchema.type).toBe("object");
    expect(m.description.length).toBeGreaterThan(10);
  }
});

test("credential tools require tabId and domain", () => {
  for (const n of ["fill_credential", "login", "fill_totp"]) {
    const req = MANIFEST.find((m) => m.name === n)!.inputSchema.required as string[];
    expect(req).toContain("tabId");
    expect(req).toContain("domain");
  }
  expect(MANIFEST.find((m) => m.name === "fill_credential")!.inputSchema.required).toContain("field");
});

test("fill_secret is keyed by NAME, not by domain — the entry is the binding", () => {
  // `domain` is the credential chain's lookup key and would be a second,
  // caller-chosen string in a tool whose whole binding comes from one entry.
  const s = MANIFEST.find((m) => m.name === "fill_secret")!.inputSchema as {
    properties: Record<string, unknown>; required: string[];
  };
  expect(s.required.sort()).toEqual(["name", "tabId"]);
  expect(Object.keys(s.properties)).not.toContain("domain");
});

// ── FIX 5 (cross-seat): the has_totp probe is a SECOND vault call that can throw ─
// Once `keychainHasTotp` learned to distinguish a fault from a miss it started
// throwing `vault_locked`, and its call site sits after `list_credentials`'s only
// try/catch. An uncaught throw there escapes the tool as a raw MCP error — the
// one shape the fixed-reason vocabulary exists to prevent.

test("FIX5: a throwing has_totp probe returns a structured reason, never throws", async () => {
  const { d } = mkDeps({
    keychainHasTotp: () => { throw new CdpError("vault_locked", `keychain denied ${PASSWORD}`); },
  });
  const r = await listCredentials({ domain: "x.com" }, d);
  expect(r).toEqual({ credentials: [], reason: "vault_locked" });
  // No metadata half-leaks out alongside the failure, and no error text either.
  expect(JSON.stringify(r)).not.toContain("alice");
  expect(JSON.stringify(r)).not.toContain(PASSWORD);
  expect(JSON.stringify(r)).not.toContain("keychain denied");
});

test("FIX5: an unrecognised has_totp failure maps to vault_error, not not_found", async () => {
  const { d } = mkDeps({ keychainHasTotp: () => { throw new Error("SQLITE_BUSY"); } });
  const r = await listCredentials({ domain: "x.com" }, d);
  expect(r).toEqual({ credentials: [], reason: "vault_error" });
  // `not_found` reads as "you have no such credential" and sends the user hunting.
  expect(r.reason).not.toBe("not_found");
});

test("FIX5: a working has_totp probe still reports both values", async () => {
  for (const has of [true, false]) {
    const { d } = mkDeps({ keychainHasTotp: () => has });
    const r = await listCredentials({ domain: "x.com" }, d);
    expect(r.reason).toBeUndefined();
    expect(r.credentials).toEqual([{ origin: "https://x.com", username: "alice", backend: "arc", has_totp: has }]);
  }
});

// ── FIX 7: one suffix list, two independent guards ──────────────────────────
// The entry-point guard and the vault-side guard are kept separate on purpose,
// but they had separate COPIES of the suffix data and the vault's copy had
// drifted 78 entries behind — so `co.ke` was refused at the door and accepted
// inside. The data is now single-sourced in src/domain.ts.

test("FIX7: both guards refuse every shared public suffix, and neither list has drifted", async () => {
  const { PUBLIC_SUFFIXES } = await import("../src/domain.ts");
  const { isRegistrableDomain } = await import("../src/vault/arc.ts");
  expect(PUBLIC_SUFFIXES.size).toBeGreaterThan(100);
  for (const s of PUBLIC_SUFFIXES) {
    expect(isValidDomain(s)).toBe(false);
    expect(isRegistrableDomain(s)).toBe(false);
  }
  // A real site under one of those suffixes is still a valid key on both sides.
  for (const ok of ["mybank.co.ke", "shop.com.au", "app.vercel.app"]) {
    expect(isValidDomain(ok)).toBe(true);
    expect(isRegistrableDomain(ok)).toBe(true);
  }
});
