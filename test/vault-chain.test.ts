import { expect, test } from "bun:test";
import { resolveCredentialWith } from "../src/vault/index.ts";
import { arcLookup, classifyCopyError } from "../src/vault/arc.ts";
import { CdpError } from "../src/cdp.ts";
import { readdirSync } from "node:fs";
import { tmpdir } from "node:os";
const cred = (u: string) => ({ origin: "https://x.com", username: u, getSecret: () => "s" });
test("arc hit wins", async () => {
  const r = await resolveCredentialWith({ arc: async () => cred("a"), keychain: async () => cred("k") }, "x.com", {});
  expect(r).toMatchObject({ backend: "arc" }); expect((r as any).cred.username).toBe("a");
});
test("falls back to keychain on arc miss", async () => {
  const r = await resolveCredentialWith({ arc: async () => null, keychain: async () => cred("k") }, "x.com", {});
  expect(r).toMatchObject({ backend: "keychain" });
});
test("reports not found with tried list", async () => {
  const r = await resolveCredentialWith({ arc: async () => null, keychain: async () => null }, "x.com", {});
  expect(r).toEqual({ found: false, tried: ["arc", "keychain"] });
});

// ── Fix round 2, item 2: an Arc read DENIAL is not an Arc MISS ──────────────

test("classifyCopyError: absent DB is a miss, denial is a fault", () => {
  expect(classifyCopyError({ code: "ENOENT" })).toBe("missing");
  for (const code of ["EACCES", "EPERM", "EPROTOTYPE"]) {
    expect(classifyCopyError({ code })).toBe("denied");
  }
  // macOS TCC surfaces as EPERM/"Operation not permitted"; unknown codes are
  // treated as denied so a fault can never masquerade as a missing credential.
  expect(classifyCopyError({ code: "EPERM", message: "Operation not permitted" })).toBe("denied");
  expect(classifyCopyError(new Error("something unexpected"))).toBe("denied");
  expect(classifyCopyError(undefined)).toBe("denied");
});

test("arcLookup THROWS vault_locked when the Login Data copy is denied", async () => {
  const denied = Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });
  let err: any;
  try { await arcLookup("x.com", { copy: () => { throw denied; } }); } catch (e) { err = e; }
  expect(err).toBeInstanceOf(CdpError);
  expect(err.code).toBe("vault_locked");
});

test("arcLookup returns null (a real miss) when Arc has no Login Data at all", async () => {
  const enoent = Object.assign(new Error("ENOENT: no such file"), { code: "ENOENT" });
  expect(await arcLookup("x.com", { copy: () => { throw enoent; } })).toBe(null);
});

test("a denied Arc read surfaces as vault_locked through the chain, NOT not_found", async () => {
  const denied = Object.assign(new Error("EPERM: operation not permitted"), { code: "EPERM" });
  let err: any;
  try {
    await resolveCredentialWith(
      { arc: (d) => arcLookup(d, { copy: () => { throw denied; } }), keychain: async () => null },
      "x.com", {},
    );
  } catch (e) { err = e; }
  expect(err?.code).toBe("vault_locked");
});

test("the temp dir is cleaned up even when the copy is denied", async () => {
  const count = () => readdirSync(tmpdir()).filter((n) => n.startsWith("apinj-")).length;
  const before = count();
  const denied = Object.assign(new Error("EACCES"), { code: "EACCES" });
  try { await arcLookup("x.com", { copy: () => { throw denied; } }); } catch { /* expected */ }
  expect(count()).toBe(before); // the new throw path must not leak a scratch dir
});

test("an absent Arc DB still falls through to keychain", async () => {
  const enoent = Object.assign(new Error("ENOENT"), { code: "ENOENT" });
  const r = await resolveCredentialWith(
    { arc: (d) => arcLookup(d, { copy: () => { throw enoent; } }), keychain: async () => cred("k") },
    "x.com", {},
  );
  expect(r).toMatchObject({ backend: "keychain" });
});

// ── Fix round 3 (vault seat) ────────────────────────────────────────────────

// ── Finding 1: an explicit `name` SELECTS; it never silently substitutes ─────

import { Database } from "bun:sqlite";
import { hostMatches, isRegistrableDomain } from "../src/vault/arc.ts";
import { keychainLookup } from "../src/vault/keychain.ts";
import { CdpError as CE } from "../src/cdp.ts";

/** Builds a real Arc-shaped Login Data DB at `dest` so arcLookup's own row
 *  selection is exercised, not a stub of it. */
function seedArcDb(rows: { origin_url: string; username_value: string }[]) {
  return (_src: string, dest: string) => {
    const db = new Database(dest, { create: true });
    db.run("CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB)");
    for (const r of rows) {
      db.run("INSERT INTO logins VALUES (?, ?, ?)", [r.origin_url, r.username_value, Buffer.from("v10zzzz")]);
    }
    db.close();
  };
}

const TWO = [
  { origin_url: "https://github.com/login", username_value: "personal" },
  { origin_url: "https://github.com/login", username_value: "work-github" },
];

test("arcLookup with no name keeps the domain-first behaviour", async () => {
  const c = await arcLookup("github.com", { copy: seedArcDb(TWO) });
  expect(c?.username).toBe("personal");
});

test("arcLookup honours an explicit name over the first domain hit", async () => {
  const c = await arcLookup("github.com", { copy: seedArcDb(TWO) }, { name: "work-github" });
  expect(c?.username).toBe("work-github");
});

test("arcLookup returns a MISS when the named credential is not in Arc", async () => {
  expect(await arcLookup("github.com", { copy: seedArcDb(TWO) }, { name: "nobody" })).toBe(null);
});

test("the chain returns the NAMED credential, not the first Arc hit", async () => {
  const r = await resolveCredentialWith(
    { arc: (d, o) => arcLookup(d, { copy: seedArcDb(TWO) }, o), keychain: async () => null },
    "github.com", { name: "work-github" },
  );
  expect((r as any).cred.username).toBe("work-github");
  expect(r).toMatchObject({ backend: "arc" });
});

test("a name that matches NOTHING is not_found — never the other credential", async () => {
  const r = await resolveCredentialWith(
    { arc: (d, o) => arcLookup(d, { copy: seedArcDb(TWO) }, o), keychain: async () => null },
    "github.com", { name: "nobody" },
  );
  expect(r).toEqual({ found: false, tried: ["arc", "keychain"] });
});

test("a backend that IGNORES the name cannot smuggle a mismatched credential through", async () => {
  // Belt-and-braces: the chain re-checks the identity it asked for.
  const r = await resolveCredentialWith(
    { arc: async () => cred("personal"), keychain: async () => null },
    "github.com", { name: "work-github" },
  );
  expect(r).toEqual({ found: false, tried: ["arc", "keychain"] });
});

test("a named Keychain entry still resolves even when its username differs", async () => {
  // The Keychain is keyed by ENTRY name; the acct inside it is the username.
  const r = await resolveCredentialWith(
    { arc: async () => null, keychain: async (n) => (n === "work-github" ? cred("alice") : null) },
    "github.com", { name: "work-github" },
  );
  expect(r).toMatchObject({ backend: "keychain" });
  expect((r as any).cred.username).toBe("alice");
});

// ── Finding 6: an Arc FAULT must not block the Keychain fallback ─────────────

test("an Arc vault_locked fault still lets a Keychain credential through", async () => {
  const r = await resolveCredentialWith(
    { arc: async () => { throw new CE("vault_locked", "Arc unreadable"); }, keychain: async () => cred("k") },
    "x.com", {},
  );
  expect(r).toMatchObject({ backend: "keychain" });
});

test("an Arc fault with NO keychain hit surfaces vault_locked, not not_found", async () => {
  let err: any;
  try {
    await resolveCredentialWith(
      { arc: async () => { throw new CE("vault_locked", "Arc unreadable"); }, keychain: async () => null },
      "x.com", {},
    );
  } catch (e) { err = e; }
  expect(err).toBeInstanceOf(CE);
  expect(err.code).toBe("vault_locked");
});

// ── Finding 4: hostMatches must match on LABEL BOUNDARIES ───────────────────

test("hostMatches refuses a bare TLD or a public suffix as the lookup key", () => {
  expect(hostMatches("auth.mybank.com", "com")).toBe(false);
  expect(hostMatches("auth.mybank.co.uk", "uk")).toBe(false);
  expect(hostMatches("auth.mybank.co.uk", "co.uk")).toBe(false);
  expect(hostMatches("x.vercel.app", "vercel.app")).toBe(false);
  expect(hostMatches("mybank.com", "")).toBe(false);
});

test("hostMatches accepts the domain itself and real subdomains", () => {
  expect(hostMatches("auth.mybank.com", "mybank.com")).toBe(true);
  expect(hostMatches("mybank.com", "mybank.com")).toBe(true);
  expect(hostMatches("a.b.mybank.com", "mybank.com")).toBe(true);
  expect(hostMatches("AUTH.MyBank.COM", "mybank.com")).toBe(true);
  expect(hostMatches("auth.mybank.co.uk", "mybank.co.uk")).toBe(true);
});

test("hostMatches is not a substring/suffix test — a look-alike host never matches", () => {
  expect(hostMatches("evilmybank.com", "mybank.com")).toBe(false);
  expect(hostMatches("mybank.com.evil.com", "mybank.com")).toBe(false);
  expect(hostMatches("notmybank.com", "mybank.com")).toBe(false);
  expect(hostMatches("mybank.com", "auth.mybank.com")).toBe(false);
  expect(hostMatches("mybank.com", "bank.com")).toBe(false);
});

test("hostMatches rejects malformed keys and hosts rather than guessing", () => {
  expect(hostMatches("auth.mybank.com", ".mybank.com")).toBe(false);
  expect(hostMatches("auth.mybank.com", "mybank..com")).toBe(false);
  expect(hostMatches("auth.mybank.com", "*.mybank.com")).toBe(false);
  expect(hostMatches("auth.mybank.com", "mybank.com:443")).toBe(false);
  expect(hostMatches("auth.mybank.com", "https://mybank.com")).toBe(false);
  expect(isRegistrableDomain("com")).toBe(false);
  expect(isRegistrableDomain("mybank.com")).toBe(true);
});

test("arcLookup will not harvest the vault via a bare-TLD domain", async () => {
  expect(await arcLookup("com", { copy: seedArcDb(TWO) })).toBe(null);
});

// ── Finding 7: a malformed Keychain entry is a FAULT, not an absence ─────────

test("an entry with no acct attribute throws instead of reading as not_found", async () => {
  let err: any;
  try { await keychainLookup("mybank", { run: () => '"svce"<blob>="apinj:mybank"\n' }); } catch (e) { err = e; }
  expect(err).toBeInstanceOf(CE);
  expect(err.code).toBe("vault_error");
});
