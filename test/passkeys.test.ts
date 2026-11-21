import { expect, test } from "bun:test";
import { passkeyLogin, passkeyRegister, type PasskeyDeps } from "../src/passkeys.ts";
import { CdpError, type Send } from "../src/cdp.ts";
import type { PasskeyEntry, PasskeyRecord } from "../src/vault/passkey.ts";
import { MANIFEST, TOOLS } from "../src/tools.ts";

// Every private key in this file is a SENTINEL. The load-bearing assertion is
// that it never appears in a tool result, whatever branch returns.
const PK = "UFJJVkFURS1LRVktU0VOVElORUwtZG8tbm90LWxlYWs=";
const ORIGIN = "https://login.example.com";
const CRED = {
  credentialId: "Q1JFRC1JRA==", isResidentCredential: true, rpId: "example.com", privateKey: PK,
  userHandle: "dWgtMQ==", signCount: 1, backupEligibility: false, backupState: false,
  userName: "agent", userDisplayName: "agent",
};

interface Page {
  origin: string; loader: string; visible: boolean; hasButton: boolean;
  /** What the authenticator does when the trigger is clicked. */
  onClick?: "register" | "assert" | "nothing";
  /** Called on each getCredentials poll: lets a test navigate mid-flight. */
  onPoll?: (p: Page) => void;
}

function mk(over: Partial<Page> = {}, depsOver: Partial<PasskeyDeps> = {}) {
  const page: Page = { origin: ORIGIN, loader: "L1", visible: true, hasButton: true, onClick: "register", ...over };
  const calls: { method: string; params: any }[] = [];
  const stored: { name: string; origin: string; rec: PasskeyRecord; opts: any }[] = [];
  let creds: any[] = [];
  let authenticators = 0;
  let consents = 0;
  const send: Send = (async (method: string, params: any = {}) => {
    calls.push({ method, params });
    switch (method) {
      case "WebAuthn.enable": case "WebAuthn.disable": return {};
      case "WebAuthn.addVirtualAuthenticator": authenticators++; return { authenticatorId: "A1" };
      case "WebAuthn.removeVirtualAuthenticator": authenticators--; return {};
      case "WebAuthn.addCredential": creds.push({ ...params.credential }); return {};
      case "WebAuthn.getCredentials":
        page.onPoll?.(page);
        return { credentials: creds };
      case "Runtime.evaluate": {
        const e: string = params.expression;
        if (e === "document.visibilityState") return { result: { value: page.visible ? "visible" : "hidden" } };
        if (e.includes(".click()")) {
          if (!page.hasButton) return { result: { value: false } };
          if (page.onClick === "register") creds.push({ ...CRED });
          if (page.onClick === "assert" && creds[0]) creds[0].signCount += 1;
          return { result: { value: true } };
        }
        return { result: {} };
      }
    }
    return {};
  }) as Send;
  const entry: PasskeyEntry = {
    origin: ORIGIN, rpId: "example.com",
    getRecord: () => ({ credentialId: CRED.credentialId, rpId: "example.com", privateKey: PK, userHandle: CRED.userHandle, signCount: 4 }),
  };
  const d: PasskeyDeps = {
    resolveTarget: async () => ({ wsUrl: "ws://stub", url: ORIGIN }),
    withConn: async (_ws, fn) => fn(send),
    getOrigin: async () => page.origin,
    getLoaderId: async () => page.loader,
    lookup: () => entry,
    store: (name, origin, rec, opts) => { stored.push({ name, origin, rec, opts }); },
    confirm: async () => { consents++; return true; },
    sleep: async () => {},
    now: (() => { let t = 0; return () => (t += 100); })(),
    ...depsOver,
  };
  return { d, page, calls, stored, get authenticators() { return authenticators; }, get consents() { return consents; } };
}

const noLeak = (r: unknown) => expect(JSON.stringify(r)).not.toContain(PK);
const methods = (calls: { method: string }[]) => calls.map((c) => c.method);

// ── register ─────────────────────────────────────────────────────────────────

test("register: stores the credential bound to the origin and returns metadata only", async () => {
  const m = mk({}, { lookup: () => null });
  const r = await passkeyRegister({ tabId: "T", name: "ex", origin: ORIGIN, selector: "#register" }, m.d);
  expect(r).toEqual({ saved: true, name: "ex", origin: ORIGIN, rpId: "example.com" });
  noLeak(r);
  expect(m.stored).toHaveLength(1);
  expect(m.stored[0].origin).toBe(ORIGIN);
  expect(m.stored[0].rec.privateKey).toBe(PK);
  expect(m.stored[0].rec.signCount).toBe(1);
  // Only the known fields are persisted.
  expect(Object.keys(m.stored[0].rec).sort()).toEqual(
    ["backupEligibility", "backupState", "credentialId", "privateKey", "rpId", "signCount", "userHandle"]);
  expect(m.authenticators).toBe(0);
  expect(methods(m.calls)).toContain("WebAuthn.disable");
  const add = m.calls.find((c) => c.method === "WebAuthn.addVirtualAuthenticator")!;
  expect(add.params.options).toMatchObject({
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
  });
});

test("register: origin mismatch refuses before consent and before any WebAuthn call", async () => {
  const m = mk({ origin: "https://evil.example.net" }, { lookup: () => null });
  const r = await passkeyRegister({ tabId: "T", name: "ex", origin: ORIGIN, selector: "#register" }, m.d);
  expect(r).toEqual({ saved: false, reason: "origin_mismatch" });
  expect(m.consents).toBe(0);
  expect(methods(m.calls).some((x) => x.startsWith("WebAuthn."))).toBe(false);
});

test("register: consent denied refuses before any WebAuthn call", async () => {
  const m = mk({}, { lookup: () => null, confirm: async () => false });
  const r = await passkeyRegister({ tabId: "T", name: "ex", origin: ORIGIN, selector: "#register" }, m.d);
  expect(r).toEqual({ saved: false, reason: "user_denied" });
  expect(methods(m.calls).some((x) => x.startsWith("WebAuthn."))).toBe(false);
});

test("register: refuses an existing entry without replace, before the gate", async () => {
  const m = mk();
  const r = await passkeyRegister({ tabId: "T", name: "ex", origin: ORIGIN }, m.d);
  expect(r).toEqual({ saved: false, reason: "exists" });
  expect(m.consents).toBe(0);
});

test("register: bad name and bad origin are refused", async () => {
  const m = mk({}, { lookup: () => null });
  expect(await passkeyRegister({ tabId: "T", name: "a b", origin: ORIGIN }, m.d)).toEqual({ saved: false, reason: "invalid_name" });
  expect(await passkeyRegister({ tabId: "T", name: "ex", origin: "http://example.com" }, m.d)).toEqual({ saved: false, reason: "invalid_origin" });
  expect(await passkeyRegister({ name: "ex", origin: ORIGIN }, m.d)).toEqual({ saved: false, reason: "tab_unavailable" });
});

test("register: hidden tab refuses with tab_not_visible and creates no authenticator", async () => {
  const m = mk({ visible: false }, { lookup: () => null });
  const r = await passkeyRegister({ tabId: "T", name: "ex", origin: ORIGIN, selector: "#register" }, m.d);
  expect(r).toEqual({ saved: false, reason: "tab_not_visible" });
  expect(methods(m.calls)).not.toContain("WebAuthn.addVirtualAuthenticator");
});

test("register: no credential before the deadline is a timeout, and the authenticator is still removed", async () => {
  const m = mk({ onClick: "nothing" }, { lookup: () => null });
  const r = await passkeyRegister({ tabId: "T", name: "ex", origin: ORIGIN, selector: "#register", timeoutMs: 2000 }, m.d);
  expect(r).toEqual({ saved: false, reason: "timeout" });
  expect(m.authenticators).toBe(0);
  expect(m.stored).toHaveLength(0);
});

test("register: missing trigger element is no_trigger", async () => {
  const m = mk({ hasButton: false }, { lookup: () => null });
  const r = await passkeyRegister({ tabId: "T", name: "ex", origin: ORIGIN, selector: "#nope" }, m.d);
  expect(r).toEqual({ saved: false, reason: "no_trigger" });
  expect(m.authenticators).toBe(0);
});

test("register: a credential for a foreign rpId is never stored", async () => {
  const m = mk({ onClick: "nothing" }, { lookup: () => null });
  m.page.onPoll = () => {};
  const orig = m.d.withConn;
  m.d.withConn = async (ws, fn) => orig(ws, async (send) => fn((async (meth: string, p: any) => {
    const r: any = await send(meth, p);
    if (meth === "WebAuthn.getCredentials") return { credentials: [{ ...CRED, rpId: "evil.net" }] };
    return r;
  }) as Send));
  const r = await passkeyRegister({ tabId: "T", name: "ex", origin: ORIGIN, selector: "#r", timeoutMs: 1000 }, m.d);
  expect(r).toEqual({ saved: false, reason: "timeout" });
  expect(m.stored).toHaveLength(0);
});

test("register: a vault write failure is vault_error, never the raw message", async () => {
  const m = mk({}, { lookup: () => null, store: () => { throw new CdpError("vault_error", PK); } });
  const r = await passkeyRegister({ tabId: "T", name: "ex", origin: ORIGIN, selector: "#register" }, m.d);
  expect(r).toEqual({ saved: false, reason: "vault_error" });
  noLeak(r);
});

// ── login ────────────────────────────────────────────────────────────────────

test("login: adds the stored credential, waits for the assertion, persists the new sign count", async () => {
  const m = mk({ onClick: "assert" });
  const r = await passkeyLogin({ tabId: "T", name: "ex", selector: "#login" }, m.d);
  expect(r).toEqual({ used: true });
  noLeak(r);
  const add = m.calls.find((c) => c.method === "WebAuthn.addCredential")!;
  expect(add.params.credential).toMatchObject({ rpId: "example.com", privateKey: PK, isResidentCredential: true, signCount: 4 });
  expect(m.stored[0].rec.signCount).toBe(5);
  expect(m.stored[0].opts).toEqual({ replace: { rpId: "example.com" } });
  expect(m.authenticators).toBe(0);
});

test("login: origin mismatch refuses before consent and before the key is read", async () => {
  let reads = 0;
  const m = mk({ origin: "https://evil.example.net" });
  const base = m.d.lookup("ex")!;
  m.d.lookup = () => ({ ...base, getRecord: () => { reads++; return base.getRecord(); } });
  const r = await passkeyLogin({ tabId: "T", name: "ex", selector: "#login" }, m.d);
  expect(r).toEqual({ used: false, reason: "origin_mismatch" });
  expect(m.consents).toBe(0);
  expect(reads).toBe(0);
  expect(methods(m.calls).some((x) => x.startsWith("WebAuthn."))).toBe(false);
});

test("login: consent denied refuses and reads no key", async () => {
  let reads = 0;
  const m = mk({}, { confirm: async () => false });
  const base = m.d.lookup("ex")!;
  m.d.lookup = () => ({ ...base, getRecord: () => { reads++; return base.getRecord(); } });
  const r = await passkeyLogin({ tabId: "T", name: "ex" }, m.d);
  expect(r).toEqual({ used: false, reason: "user_denied" });
  expect(reads).toBe(0);
});

test("login: not_found, no_origin_binding, vault_locked", async () => {
  expect(await passkeyLogin({ tabId: "T", name: "ex" }, mk({}, { lookup: () => null }).d)).toEqual({ used: false, reason: "not_found" });
  const unbound = mk({}, { lookup: () => ({ origin: "", rpId: "example.com", getRecord: () => { throw new Error("no"); } }) });
  expect(await passkeyLogin({ tabId: "T", name: "ex" }, unbound.d)).toEqual({ used: false, reason: "no_origin_binding" });
  const locked = mk({}, { lookup: () => { throw new CdpError("vault_locked", PK); } });
  const r = await passkeyLogin({ tabId: "T", name: "ex" }, locked.d);
  expect(r).toEqual({ used: false, reason: "vault_locked" });
  noLeak(r);
});

test("login: navigation after consent aborts before addCredential", async () => {
  const m = mk({ onClick: "assert" }, {
    confirm: async () => { m.page.loader = "L2"; return true; },
  });
  const r = await passkeyLogin({ tabId: "T", name: "ex", selector: "#login" }, m.d);
  expect(r).toEqual({ used: false, reason: "navigated_during_consent" });
  expect(methods(m.calls)).not.toContain("WebAuthn.addCredential");
});

test("login: no assertion before the deadline is a timeout; nothing persisted; authenticator removed", async () => {
  const m = mk({ onClick: "nothing" });
  const r = await passkeyLogin({ tabId: "T", name: "ex", selector: "#login", timeoutMs: 1500 }, m.d);
  expect(r).toEqual({ used: false, reason: "timeout" });
  expect(m.stored).toHaveLength(0);
  expect(m.authenticators).toBe(0);
});

test("login: a CDP fault mid-flight still removes the authenticator and leaks nothing", async () => {
  const m = mk({ onClick: "assert" });
  const orig = m.d.withConn;
  m.d.withConn = async (ws, fn) => orig(ws, async (send) => fn((async (meth: string, p: any) => {
    if (meth === "WebAuthn.addCredential") { await send(meth, p); throw new CdpError("cdp_error", PK); }
    return send(meth, p);
  }) as Send));
  const r = await passkeyLogin({ tabId: "T", name: "ex", selector: "#login" }, m.d);
  expect(r).toEqual({ used: false, reason: "tab_unavailable" });
  noLeak(r);
  expect(m.authenticators).toBe(0);
});

test("timeouts are clamped below the ~30 s gateway limit", async () => {
  let waited = 0;
  const m = mk({ onClick: "nothing" }, { sleep: async (ms) => { waited += ms; }, now: (() => { let t = 0; return () => (t += 250); })() });
  const t0 = Date.now();
  await passkeyLogin({ tabId: "T", name: "ex", selector: "#login", timeoutMs: 10 * 60_000 }, m.d);
  expect(Date.now() - t0).toBeLessThan(2000);
  // 25 s cap at 250 ms per tick (now() advances 250 per call): far fewer than 10 min of ticks.
  expect(waited).toBeLessThanOrEqual(25_000);
});

// ── registry ─────────────────────────────────────────────────────────────────

test("passkey tools are registered with strict schemas", () => {
  const names = MANIFEST.map((t) => t.name);
  expect(names).toContain("passkey_register");
  expect(names).toContain("passkey_login");
  expect(typeof TOOLS.passkey_register).toBe("function");
  for (const n of ["passkey_register", "passkey_login"]) {
    const s = MANIFEST.find((t) => t.name === n)!.inputSchema as any;
    expect(s.additionalProperties).toBe(false);
    expect(JSON.stringify(s)).not.toContain("privateKey");
  }
});

test("issue #1: a slow Allow shortens the ceremony wait so the call stays inside the budget", async () => {
  let waited = 0;
  let t = 0;
  const m = mk({ onClick: "nothing" }, {
    sleep: async (ms) => { waited += ms; t += ms; },
    now: () => t,
    confirm: async () => { t += 20_000; return true; }, // 20 s to click Allow
  });
  const r = await passkeyLogin({ tabId: "T", name: "ex", selector: "#login", timeoutMs: 20_000 }, m.d);
  expect(r).toEqual({ used: false, reason: "timeout" });
  expect(waited).toBe(5_000); // 25 s budget - 20 s in the dialog
});
