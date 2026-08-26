import { expect, test } from "bun:test";
import { fillSecret, fillTotp, login, type Deps } from "../src/tools.ts";
import { CdpError, type Send } from "../src/cdp.ts";

// ── The load-bearing test ────────────────────────────────────────────────────
// The entire point of this MCP is that the model never sees a credential. This
// file proves the injected secret crosses NO tool boundary — not in a return
// value, not in a thrown error's message — across every return branch of
// `login` and `fillTotp`. A mutation check at the bottom proves the assertions
// here are non-vacuous: they actually fail when a secret leaks.

const SENTINEL = "S3NT1NEL-do-not-leak";
const SEED = "S3NT1NEL-SEED-JBSWY3DPEHPK3PXP";
/** A nine-digit sentinel, so the shaped formats are exercised too. */
const SSN = "987654321";

const ORIGIN = "https://x.com";
const ARGS = { tabId: "T1", domain: "x.com" };
const SARGS = { tabId: "T1", name: "ssn-full" };

const send: Send = (async (_method: string, _params: any) => ({ result: {} })) as Send;

const CRED = { origin: ORIGIN, username: "alice", getSecret: () => SENTINEL };
const SECRET = { origin: ORIGIN, flags: { kind: "text" }, getSecret: () => SSN };

/** Base stub deps for a wired-up, working flow. Overridden per-branch below. */
function baseDeps(over: Partial<Deps> = {}): Deps {
  return {
    resolveCredential: async () => ({ cred: CRED, backend: "arc" }),
    resolveSecret: async () => SECRET,
    resolveTarget: async () => ({ wsUrl: "ws://stub", url: `${ORIGIN}/login` }),
    withConn: async (_ws, fn) => fn(send),
    getOrigin: async () => ORIGIN,
    getLoaderId: async () => "LOADER-1",
    confirmInjection: async () => true,
    confirmSecret: async () => true,
    detectLoginFields: async () => ({ user: "#u", pass: "#p" }),
    typeIntoField: async () => {},
    probeFields: async (_s, attr, token) => [
      { sel: `[${attr}="${token}-0"]`, type: "text", name: "ssn", id: "", placeholder: "",
        label: "", autocomplete: "", focused: false },
    ],
    inspectField: async () => ({ type: "text", visible: true }),
    totpCode: () => "654321",
    keychainHasTotp: () => true,
    keychainTotpSeed: () => SEED,
    ...over,
  };
}

function assertNoLeak(result: unknown) {
  const json = JSON.stringify(result);
  expect(json).not.toContain(SENTINEL);
  expect(json).not.toContain(SEED);
  expect(json).not.toContain(SSN);
}

// ── login: every return branch ───────────────────────────────────────────────

test("login: user_denied branch never leaks the secret", async () => {
  const d = baseDeps({ confirmInjection: async () => false });
  const result = await login(ARGS, d).catch((e) => ({ error: String(e) }));
  assertNoLeak(result);
});

test("login: origin_mismatch branch never leaks the secret", async () => {
  const d = baseDeps({ getOrigin: async () => "https://evil.com" });
  const result = await login(ARGS, d).catch((e) => ({ error: String(e) }));
  assertNoLeak(result);
});

test("login: not_found branch never leaks the secret", async () => {
  const d = baseDeps({ resolveCredential: async () => ({ found: false, tried: ["arc", "keychain"] }) });
  const result = await login(ARGS, d).catch((e) => ({ error: String(e) }));
  assertNoLeak(result);
});

test("login: happy path never leaks the secret in the return, but DOES type it into the DOM", async () => {
  const typed: { sel: string; value: string }[] = [];
  const d = baseDeps({
    typeIntoField: async (_s, sel, value) => { typed.push({ sel, value }); },
  });
  const result = await login(ARGS, d).catch((e) => ({ error: String(e) }));
  assertNoLeak(result);
  expect(result).toEqual({ filled: true, submitted: false });
  // Proves the absence-from-return assertion above is meaningful, not vacuous:
  // the secret really did flow to the DOM via typeIntoField.
  expect(typed.some((t) => t.value === SENTINEL)).toBe(true);
});

// ── fill_totp: seed and generated code never leak ───────────────────────────

test("fill_totp: happy path never leaks the seed or the generated code", async () => {
  const typed: { sel: string; value: string }[] = [];
  const d = baseDeps({
    probeFields: async (_s, attr, token) => [
      { sel: `[${attr}="${token}-0"]`, type: "text", name: "otp", id: "", placeholder: "",
        label: "", autocomplete: "one-time-code", focused: false },
    ],
    typeIntoField: async (_s, sel, value) => { typed.push({ sel, value }); },
    totpCode: (seed) => (seed === SEED ? "111222" : "000000"),
  });
  const result = await fillTotp(ARGS, d).catch((e) => ({ error: String(e) }));
  assertNoLeak(result);
  const json = JSON.stringify(result);
  expect(json).not.toContain("111222");
  expect(result).toEqual({ filled: true });
  // The code really was typed — proves the return-side absence is meaningful.
  expect(typed.some((t) => t.value === "111222")).toBe(true);
});

test("fill_totp: user_denied branch never leaks the seed", async () => {
  const d = baseDeps({ confirmInjection: async () => false });
  const result = await fillTotp(ARGS, d).catch((e) => ({ error: String(e) }));
  assertNoLeak(result);
});

test("fill_totp: origin_mismatch branch never leaks the seed", async () => {
  const d = baseDeps({ getOrigin: async () => "https://evil.com" });
  const result = await fillTotp(ARGS, d).catch((e) => ({ error: String(e) }));
  assertNoLeak(result);
});

test("fill_totp: not_found branch never leaks the seed", async () => {
  const d = baseDeps({ resolveCredential: async () => ({ found: false, tried: ["arc", "keychain"] }) });
  const result = await fillTotp(ARGS, d).catch((e) => ({ error: String(e) }));
  assertNoLeak(result);
});

// ── fill_secret: the value, its LENGTH, and any mask ────────────────────────
//
// The reference implementation printed {ok, field_len, masked} for read-back
// verification, and its masking was wrong twice in one day: a naive `len >= 8`
// test printed the last two digits of a dashed SSN (11 chars), and a segmented
// box holding 2-4 digits has "last two" as most of the secret. Both bugs shared
// one root cause — secrecy is a property of the FORMAT, not the length. This
// server returns {filled, reason?} and nothing else, on every branch, which is
// the only shape that cannot be wrong in that way.

const SECRET_BRANCHES: [string, Partial<Deps> | undefined, object][] = [
  ["happy path", undefined, SARGS],
  ["user_denied", { confirmSecret: async () => false }, SARGS],
  ["origin_mismatch", { getOrigin: async () => "https://evil.com" }, SARGS],
  ["not_found", { resolveSecret: async () => null }, SARGS],
  ["no_origin_binding", { resolveSecret: async () => ({ ...SECRET, origin: "" }) }, SARGS],
  ["vault_locked at lookup", { resolveSecret: async () => { throw new CdpError("vault_locked", SSN); } }, SARGS],
  ["vault fault at read", {
    resolveSecret: async () => ({ ...SECRET, getSecret: () => { throw new CdpError("vault_locked", SSN); } }),
  }, SARGS],
  ["selector_not_allowed", { resolveSecret: async () => ({ ...SECRET, flags: {} }) }, { ...SARGS, selector: "#x" }],
  ["kind_not_allowed", { resolveSecret: async () => ({ ...SECRET, flags: { sel: "allow" } }) }, { ...SARGS, selector: "#x" }],
  ["field_not_visible", { inspectField: async () => ({ type: "text", visible: false }) }, SARGS],
  ["no_secret_field", { probeFields: async () => [] }, SARGS],
  ["ambiguous_secret_field", {
    probeFields: async (_s, attr, token) => [0, 1].map((i) => ({
      sel: `[${attr}="${token}-${i}"]`, type: "text", name: "", id: "", placeholder: "",
      label: "", autocomplete: "", focused: false,
    })),
  }, SARGS],
  ["tab_unavailable", { resolveTarget: async () => { throw new CdpError("tab_unavailable", "gone"); } }, SARGS],
  ["bad_name", undefined, { tabId: "T1", name: "not a name" }],
  ["bad_format", undefined, { ...SARGS, format: "sneaky" }],
  ["format_mismatch", { resolveSecret: async () => ({ ...SECRET, getSecret: () => "4321" }) }, { ...SARGS, format: "last4" }],
];

for (const [label, over, args] of SECRET_BRANCHES) {
  test(`fill_secret: the ${label} branch never leaks the secret`, async () => {
    const d = baseDeps(over);
    const result = await fillSecret(args, d).catch((e) => ({ error: String(e) }));
    assertNoLeak(result);
    // Not just the value: no length and no mask of it either.
    const json = JSON.stringify(result);
    expect(json).not.toContain('"length"');
    expect(json).not.toContain("masked");
    expect(json).not.toContain("*");
    expect(json).not.toContain(String(SSN.length));
  });
}

test("fill_secret: the return shape is EXACTLY {filled} or {filled, reason}", async () => {
  for (const [, over, args] of SECRET_BRANCHES) {
    const r = await fillSecret(args, baseDeps(over)) as Record<string, unknown>;
    expect(Object.keys(r).sort()).toEqual(r.filled ? ["filled"] : ["filled", "reason"]);
  }
});

test("fill_secret: the absence-assertions are NOT vacuous — the SSN really reaches the DOM", async () => {
  const typed: string[] = [];
  const d = baseDeps({ typeIntoField: async (_s, _sel, value) => { typed.push(value); } });
  const result = await fillSecret(SARGS, d);
  assertNoLeak(result);
  expect(result).toEqual({ filled: true });
  expect(typed).toEqual([SSN]);
});

test("fill_secret: a SHAPED value reaches the DOM and still never reaches the caller", async () => {
  const typed: string[] = [];
  const d = baseDeps({ typeIntoField: async (_s, _sel, value) => { typed.push(value); } });
  const result = await fillSecret({ ...SARGS, format: "dashed" }, d);
  assertNoLeak(result);
  expect(JSON.stringify(result)).not.toContain("987-65-4321");
  expect(typed).toEqual(["987-65-4321"]);
});

test("fill_secret: a vault error MESSAGE carrying the secret never reaches the reason", async () => {
  // The thrown CdpError above is constructed with the SSN as its message, which
  // is the shape a careless `catch (e) { return fail(e.message) }` would leak.
  const d = baseDeps({
    resolveSecret: async () => ({ ...SECRET, getSecret: () => { throw new CdpError("vault_locked", SSN); } }),
  });
  const r = await fillSecret(SARGS, d);
  expect(r).toEqual({ filled: false, reason: "vault_locked" });
});
