import { expect, test } from "bun:test";
import { decideGate } from "../src/gate.ts";
import { CdpError } from "../src/cdp.ts";

const base = { tabOrigin: "https://x.com", savedOrigin: "https://x.com", allow: true };

test("passes when origin matches and user allows", () => expect(decideGate(base)).toEqual({ ok: true }));

test("blocks on origin mismatch BEFORE consent", () => {
  expect(decideGate({ ...base, tabOrigin: "https://evil.com" })).toEqual({ ok: false, reason: "origin_mismatch" });
});

test("blocks when user denies", () => expect(decideGate({ ...base, allow: false })).toEqual({ ok: false, reason: "user_denied" }));

// Invariant #1: origin-match is checked FIRST. A mismatch must short-circuit with
// origin_mismatch even when the user would have allowed — and, critically, even when
// the user denied, the *origin* is the reason reported, proving the ordering.
test("origin mismatch wins over user_denied (order proof)", () => {
  expect(decideGate({ tabOrigin: "https://evil.com", savedOrigin: "https://x.com", allow: false }))
    .toEqual({ ok: false, reason: "origin_mismatch" });
});

test("scheme mismatch is an origin mismatch", () => {
  expect(decideGate({ ...base, tabOrigin: "http://x.com" })).toEqual({ ok: false, reason: "origin_mismatch" });
});

test("port mismatch is an origin mismatch", () => {
  expect(decideGate({ tabOrigin: "https://x.com:8443", savedOrigin: "https://x.com", allow: true }))
    .toEqual({ ok: false, reason: "origin_mismatch" });
});

test("subdomain is NOT an origin match", () => {
  expect(decideGate({ ...base, tabOrigin: "https://evil.x.com" })).toEqual({ ok: false, reason: "origin_mismatch" });
});

test("an empty/unreadable tab origin blocks", () => {
  expect(decideGate({ ...base, tabOrigin: "" })).toEqual({ ok: false, reason: "origin_mismatch" });
});

test("default https port is equivalent to no port", () => {
  expect(decideGate({ tabOrigin: "https://x.com:443", savedOrigin: "https://x.com", allow: true })).toEqual({ ok: true });
});

// ── fill_secret: the two capabilities a stored entry can grant ───────────────
//
// `fill_secret` exists to reach fields `fill_credential` deliberately will not:
// an SSN box, a freeze PIN, a segmented date of birth. Doing that safely rests
// on exactly two flags, both DENY by default, both set by a human with
// `security` at storage time rather than by the caller at call time:
//
//   sel=allow   the caller may name the field
//   kind=text   the secret may land in a non-password input
//
// These tests matter more than the happy path: they are the boundary. A caller
// steered by page content must not be able to name a visible attacker-controlled
// input and have the SSN render on screen.

import { fillSecret, type Deps } from "../src/tools.ts";
import type { Send } from "../src/cdp.ts";
import type { SecretEntry } from "../src/vault/keychain.ts";
import type { FieldInfo } from "../src/tools.ts";

const SSN = "123456789";
const SECRET_ORIGIN = "https://www.experian.com";

interface SecretSpy { consent: number; typed: { sel: string; value: string }[]; probes: number }

function secretDeps(over: {
  flags?: Record<string, string>;
  origin?: string;
  page?: Partial<FieldInfo>[];
  field?: { type: string; visible: boolean } | null;
  entry?: SecretEntry | null;
  deps?: Partial<Deps>;
} = {}): { d: Deps; spy: SecretSpy } {
  const spy: SecretSpy = { consent: 0, typed: [], probes: 0 };
  const page = over.page ?? [{ type: "password" }];
  const send: Send = (async () => ({ result: {} })) as Send;
  const d: Deps = {
    resolveCredential: async () => ({ found: false, tried: [] }),
    resolveSecret: async () =>
      over.entry !== undefined ? over.entry : {
        origin: over.origin ?? SECRET_ORIGIN,
        flags: over.flags ?? {},
        getSecret: () => SSN,
      },
    resolveTarget: async () => ({ wsUrl: "ws://stub", url: `${SECRET_ORIGIN}/x` }),
    withConn: async (_ws, fn) => fn(send),
    getOrigin: async () => over.origin ?? SECRET_ORIGIN,
    getLoaderId: async () => "LOADER-1",
    confirmInjection: async () => true,
    confirmSecret: async () => { spy.consent++; return true; },
    detectLoginFields: async () => ({}),
    typeIntoField: async (_s, sel, value) => { spy.typed.push({ sel, value }); },
    probeFields: async (_s, attr, token) => {
      spy.probes++;
      return page.map((x, i) => ({
        sel: `[${attr}="${token}-${i}"]`, type: "text", name: "", id: "", placeholder: "",
        label: "", autocomplete: "", focused: false, ...x,
      })) as FieldInfo[];
    },
    inspectField: async (_s, sel) => {
      if (over.field !== undefined) return over.field;
      const i = page.findIndex((_p, n) => sel.includes(`-${n}"]`));
      const p = i >= 0 ? page[i] : undefined;
      return { type: (p?.type as string) ?? "text", visible: true };
    },
    totpCode: () => "123456",
    keychainHasTotp: () => false,
    keychainTotpSeed: () => null,
    ...over.deps,
  };
  return { d, spy };
}

const SARGS = { tabId: "T1", name: "ssn-full" };

// ── sel: caller-supplied selector control ────────────────────────────────────

test("SEL: a selector on an entry WITHOUT sel=allow is refused, with no consent prompt", async () => {
  const { d, spy } = secretDeps({ flags: { kind: "text" } });
  expect(await fillSecret({ ...SARGS, selector: "#attacker-visible-box" }, d))
    .toEqual({ filled: false, reason: "selector_not_allowed" });
  // Refused before the dialog: a caller must not be able to make a human answer
  // a prompt about a fill that was never going to be permitted.
  expect(spy.consent).toBe(0);
  expect(spy.typed).toEqual([]);
});

test("SEL: sel=allow honours the selector and skips the probe entirely", async () => {
  const { d, spy } = secretDeps({ flags: { sel: "allow", kind: "text" } });
  expect(await fillSecret({ ...SARGS, selector: "#ssn" }, d)).toEqual({ filled: true });
  expect(spy.probes).toBe(0);
  expect(spy.typed).toEqual([{ sel: "#ssn", value: SSN }]);
});

test("SEL: the grant must be the literal string 'allow' — anything else denies", async () => {
  for (const v of ["ALLOW", "allowed", "yes", "true", "1", "deny", ""]) {
    const { d } = secretDeps({ flags: { sel: v, kind: "text" } });
    expect(await fillSecret({ ...SARGS, selector: "#ssn" }, d))
      .toEqual({ filled: false, reason: "selector_not_allowed" });
  }
});

test("SEL: with no selector supplied, an entry without sel=allow still works by auto-detect", async () => {
  // The flag governs CALLER control of the field, not the tool's own detection.
  const { d, spy } = secretDeps({ flags: {}, page: [{ type: "password" }] });
  expect(await fillSecret(SARGS, d)).toEqual({ filled: true });
  expect(spy.probes).toBe(1);
});

// ── kind: which field type a secret may land in ──────────────────────────────

test("KIND: without kind=text, a non-password field is refused even WITH sel=allow", async () => {
  // This is the protection chooseFields gets for free by keying on
  // type === "password". A selector grant must not silently carry it away.
  const { d, spy } = secretDeps({ flags: { sel: "allow" }, field: { type: "text", visible: true } });
  expect(await fillSecret({ ...SARGS, selector: "#ssn" }, d))
    .toEqual({ filled: false, reason: "kind_not_allowed" });
  expect(spy.typed).toEqual([]);
});

test("KIND: without kind=text, auto-detect will only ever pick a password box", async () => {
  const { d, spy } = secretDeps({ flags: {}, page: [{ type: "text", name: "ssn" }] });
  expect(await fillSecret(SARGS, d)).toEqual({ filled: false, reason: "no_secret_field" });
  expect(spy.typed).toEqual([]);
});

test("KIND: kind=text permits the text box an SSN actually lives in", async () => {
  const { d, spy } = secretDeps({ flags: { kind: "text" }, page: [{ type: "text", name: "ssn" }] });
  expect(await fillSecret(SARGS, d)).toEqual({ filled: true });
  expect(spy.typed[0].value).toBe(SSN);
});

test("KIND: the grant must be the literal string 'text' — anything else denies", async () => {
  for (const v of ["TEXT", "any", "true", "1", ""]) {
    const { d } = secretDeps({ flags: { sel: "allow", kind: v }, field: { type: "text", visible: true } });
    expect(await fillSecret({ ...SARGS, selector: "#ssn" }, d))
      .toEqual({ filled: false, reason: "kind_not_allowed" });
  }
});

test("KIND: the field type is re-read on the SELECTOR path, not trusted from the argument", async () => {
  // The selector path never sees a probe, so this inspection is the only place
  // `kind` can be enforced at all.
  const inspected: string[] = [];
  const { d } = secretDeps({
    flags: { sel: "allow" },
    field: { type: "text", visible: true },
    deps: { inspectField: async (_s, sel) => { inspected.push(sel); return { type: "text", visible: true }; } },
  });
  expect((await fillSecret({ ...SARGS, selector: "#ssn" }, d)).reason).toBe("kind_not_allowed");
  expect(inspected).toEqual(["#ssn"]);
});

// ── The field must be one a human could see ──────────────────────────────────

test("VISIBLE: an invisible target is refused — focus alone does not rule one out", async () => {
  // An opacity:0 input still takes focus, so the focus verification inside
  // typeIntoField would have passed and the SSN would have gone into a box
  // nobody can see.
  const { d, spy } = secretDeps({
    flags: { sel: "allow", kind: "text" },
    field: { type: "text", visible: false },
  });
  expect(await fillSecret({ ...SARGS, selector: "#hidden" }, d))
    .toEqual({ filled: false, reason: "field_not_visible" });
  expect(spy.typed).toEqual([]);
});

test("VISIBLE: a selector that resolves to nothing is no_secret_field, not a guess", async () => {
  const { d, spy } = secretDeps({ flags: { sel: "allow", kind: "text" }, field: null });
  expect(await fillSecret({ ...SARGS, selector: "#gone" }, d))
    .toEqual({ filled: false, reason: "no_secret_field" });
  expect(spy.typed).toEqual([]);
});

// ── Ambiguity refuses, exactly as it does for a password ─────────────────────

test("AMBIGUOUS: two candidate fields refuse rather than guessing", async () => {
  const { d, spy } = secretDeps({
    flags: { kind: "text" },
    page: [{ type: "text", name: "ssn" }, { type: "text", name: "dob" }],
  });
  expect(await fillSecret(SARGS, d)).toEqual({ filled: false, reason: "ambiguous_secret_field" });
  expect(spy.typed).toEqual([]);
});

test("AMBIGUOUS: an attacker ADDING an input creates ambiguity, so it refuses", async () => {
  // The property that makes sole-candidate detection safe: script on the matched
  // origin can deny the fill, but cannot redirect it.
  const { d } = secretDeps({ flags: {}, page: [{ type: "password" }, { type: "password" }] });
  expect((await fillSecret(SARGS, d)).reason).toBe("ambiguous_secret_field");
});

test("AMBIGUOUS: focus is NOT a tiebreak — one line of page script would own it", async () => {
  const { d } = secretDeps({
    flags: { kind: "text" },
    page: [{ type: "text", name: "ssn" }, { type: "text", name: "evil", focused: true }],
  });
  expect((await fillSecret(SARGS, d)).reason).toBe("ambiguous_secret_field");
});

// ── The binding, the vault, and the argument surface ─────────────────────────

test("BIND: a secret with no stored origin fails closed, without prompting", async () => {
  const { d, spy } = secretDeps({ origin: "", flags: { kind: "text" } });
  expect(await fillSecret(SARGS, d)).toEqual({ filled: false, reason: "no_origin_binding" });
  expect(spy.consent).toBe(0);
});

test("BIND: a tab whose origin differs from the stored one never prompts", async () => {
  const { d, spy } = secretDeps({
    flags: { kind: "text" },
    deps: { getOrigin: async () => "https://evil.com" },
  });
  expect(await fillSecret(SARGS, d)).toEqual({ filled: false, reason: "origin_mismatch" });
  expect(spy.consent).toBe(0);
  expect(spy.typed).toEqual([]);
});

test("BIND: a denied dialog types nothing", async () => {
  const { d, spy } = secretDeps({
    flags: { kind: "text" },
    deps: { confirmSecret: async () => false },
  });
  expect(await fillSecret(SARGS, d)).toEqual({ filled: false, reason: "user_denied" });
  expect(spy.typed).toEqual([]);
});

test("BIND: the consent dialog names the entry, not just the host", async () => {
  const seen: [string, string][] = [];
  const { d } = secretDeps({
    flags: { kind: "text" },
    deps: { confirmSecret: async (o, n) => { seen.push([o, n]); return true; } },
  });
  await fillSecret(SARGS, d);
  expect(seen).toEqual([[SECRET_ORIGIN, "ssn-full"]]);
});

test("VAULT: fill_secret resolves KEYCHAIN-ONLY — the credential chain is never consulted", async () => {
  // resolveCredential would try Arc first and could hand back a saved LOGIN whose
  // username happens to equal the name: a different value, from a backend with no
  // sel/kind flags. That is the substitution rule 1 forbids, by the back door.
  let credCalls = 0;
  const { d } = secretDeps({
    flags: { kind: "text" },
    deps: { resolveCredential: async () => { credCalls++; return { found: false, tried: [] }; } },
  });
  expect(await fillSecret(SARGS, d)).toEqual({ filled: true });
  expect(credCalls).toBe(0);
});

test("ARGS: a missing name is name_required, a malformed one is bad_name — neither is not_found", async () => {
  const { d, spy } = secretDeps();
  expect(await fillSecret({ tabId: "T1" }, d)).toEqual({ filled: false, reason: "name_required" });
  for (const bad of ["../etc/passwd", "a b", 'x"y', "-lead", "a".repeat(65), "ssn\nfull"]) {
    expect(await fillSecret({ tabId: "T1", name: bad }, d)).toEqual({ filled: false, reason: "bad_name" });
  }
  expect(spy.consent).toBe(0);
});

test("ARGS: a name that matches no entry is not_found, never a substitution", async () => {
  const { d } = secretDeps({ entry: null });
  expect(await fillSecret(SARGS, d)).toEqual({ filled: false, reason: "not_found" });
});

test("ARGS: an unknown format is refused before the vault is read", async () => {
  let reads = 0;
  const { d } = secretDeps({ deps: { resolveSecret: async () => { reads++; return null; } } });
  expect(await fillSecret({ ...SARGS, format: "sneaky" }, d)).toEqual({ filled: false, reason: "bad_format" });
  expect(reads).toBe(0);
});

test("ARGS: a missing tabId is tab_unavailable, with no vault read", async () => {
  let reads = 0;
  const { d } = secretDeps({ deps: { resolveSecret: async () => { reads++; return null; } } });
  expect(await fillSecret({ name: "ssn-full" }, d)).toEqual({ filled: false, reason: "tab_unavailable" });
  expect(reads).toBe(0);
});

// ── Format shaping reaches the DOM, not the caller ──────────────────────────

test("FORMAT: each shape is what lands in the field", async () => {
  for (const [format, expected] of [
    ["raw", "123456789"], ["dashed", "123-45-6789"],
    ["last4", "6789"], ["first3", "123"], ["mid2", "45"],
  ] as const) {
    const { d, spy } = secretDeps({ flags: { kind: "text" }, page: [{ type: "text" }] });
    expect(await fillSecret({ ...SARGS, format }, d)).toEqual({ filled: true });
    expect(spy.typed[0].value).toBe(expected);
  }
});

test("FORMAT: a stored value that is not nine digits refuses rather than sending", async () => {
  const { d, spy } = secretDeps({
    flags: { kind: "text" },
    page: [{ type: "text" }],
    deps: { resolveSecret: async () => ({ origin: SECRET_ORIGIN, flags: { kind: "text" }, getSecret: () => "6789" }) },
  });
  expect(await fillSecret({ ...SARGS, format: "last4" }, d))
    .toEqual({ filled: false, reason: "format_mismatch" });
  expect(spy.typed).toEqual([]);
});

test("FORMAT: a vault fault at read time stays a vault fault, not format_mismatch", async () => {
  const { d } = secretDeps({
    flags: { kind: "text" },
    page: [{ type: "text" }],
    deps: {
      resolveSecret: async () => ({
        origin: SECRET_ORIGIN, flags: { kind: "text" },
        getSecret: () => { throw new CdpError("vault_locked", "denied"); },
      }),
    },
  });
  expect(await fillSecret(SARGS, d)).toEqual({ filled: false, reason: "vault_locked" });
});

test("EVENTS: the opt-in reaches typeIntoField, and is off by default", async () => {
  const seen: (boolean | undefined)[] = [];
  const mk = (args: object) => secretDeps({
    flags: { kind: "text" },
    deps: { typeIntoField: async (_s, _sel, _v, _g, o) => { seen.push(o?.events); } },
  });
  await fillSecret(SARGS, mk({}).d);
  await fillSecret({ ...SARGS, events: true }, mk({}).d);
  expect(seen).toEqual([false, true]);
});
