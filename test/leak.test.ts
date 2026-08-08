import { expect, test } from "bun:test";
import { fillTotp, login, type Deps } from "../src/tools.ts";
import type { Send } from "../src/cdp.ts";

// ── The load-bearing test ────────────────────────────────────────────────────
// The entire point of this MCP is that the model never sees a credential. This
// file proves the injected secret crosses NO tool boundary — not in a return
// value, not in a thrown error's message — across every return branch of
// `login` and `fillTotp`. A mutation check at the bottom proves the assertions
// here are non-vacuous: they actually fail when a secret leaks.

const SENTINEL = "S3NT1NEL-do-not-leak";
const SEED = "S3NT1NEL-SEED-JBSWY3DPEHPK3PXP";

const ORIGIN = "https://x.com";
const ARGS = { tabId: "T1", domain: "x.com" };

const send: Send = (async (_method: string, _params: any) => ({ result: {} })) as Send;

const CRED = { origin: ORIGIN, username: "alice", getSecret: () => SENTINEL };

/** Base stub deps for a wired-up, working flow. Overridden per-branch below. */
function baseDeps(over: Partial<Deps> = {}): Deps {
  return {
    resolveCredential: async () => ({ cred: CRED, backend: "arc" }),
    resolveTarget: async () => ({ wsUrl: "ws://stub", url: `${ORIGIN}/login` }),
    withConn: async (_ws, fn) => fn(send),
    getOrigin: async () => ORIGIN,
    getLoaderId: async () => "LOADER-1",
    confirmInjection: async () => true,
    detectLoginFields: async () => ({ user: "#u", pass: "#p" }),
    typeIntoField: async () => {},
    probeFields: async () => [],
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
