import { expect, test } from "bun:test";
import { isItemNotFound, parseAcct, parseComment } from "../src/vault/keychain.ts";
test("parseAcct pulls the account attribute from security -g output", () => {
  const out = 'keychain: "/Users/x/Library/Keychains/login.keychain-db"\n"acct"<blob>="alice@example.com"\n"svce"<blob>="apinj:mybank"';
  expect(parseAcct(out)).toBe("alice@example.com");
});
test("parseAcct returns null when absent", () => expect(parseAcct("nope")).toBe(null));

// ── Origin binding (fix round 1, finding 5) ─────────────────────────────────

test("parseComment reads the bound origin from the comment attribute", () => {
  const out = '"acct"<blob>="alice"\n"icmt"<blob>="https://auth.mybank.com"\n"svce"<blob>="apinj:mybank"';
  expect(parseComment(out)).toBe("https://auth.mybank.com");
});

test("parseComment returns empty when the entry has no comment", () => {
  expect(parseComment('"acct"<blob>="alice"\n"icmt"<blob>=<NULL>')).toBe("");
  expect(parseComment('"acct"<blob>="alice"')).toBe("");
});

// ── Fault vs miss (fix round 1, finding 3) ──────────────────────────────────

test("isItemNotFound is true only for errSecItemNotFound (status 44)", () => {
  expect(isItemNotFound({ status: 44 })).toBe(true);
});

test("isItemNotFound is FALSE for access denial — a fault must not read as a miss", () => {
  // 51 = "User interaction is not allowed", 36 = errSecInteractionNotAllowed-ish.
  expect(isItemNotFound({ status: 51, stderr: "User interaction is not allowed." })).toBe(false);
  expect(isItemNotFound({ status: 36, stderr: "The user name or passphrase you entered is not correct." })).toBe(false);
  expect(isItemNotFound({ status: 1, stderr: "SecKeychainSearchCopyNext: authorization denied" })).toBe(false);
});

test("isItemNotFound falls back to the stderr text when no status is present", () => {
  expect(isItemNotFound({ stderr: "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain." })).toBe(true);
  expect(isItemNotFound({ stderr: "authorization denied" })).toBe(false);
  expect(isItemNotFound({})).toBe(false);
});

// ── Fix round 3 (vault seat) ────────────────────────────────────────────────

import { keychainLookup, keychainHasTotp, keychainTotpSeed } from "../src/vault/keychain.ts";
import { CdpError } from "../src/cdp.ts";

const ATTRS = '"acct"<blob>="alice"\n"icmt"<blob>="https://auth.mybank.com"\n"svce"<blob>="apinj:mybank"';
const notFound = () => Object.assign(new Error("could not be found"), { status: 44 });
const denied = () => Object.assign(new Error("denied"), { status: 51, stderr: "User interaction is not allowed." });

/** Records every `security` invocation so the PASSWORD reads (`-w`) can be counted. */
function spyRun(handler: (args: string[]) => string) {
  const calls: string[][] = [];
  const run = (args: string[]) => { calls.push(args); return handler(args); };
  return { run, calls, pwReads: () => calls.filter((a) => a.includes("-w")).length };
}

// ── Finding 2: the plaintext is read LAZILY, never at lookup ────────────────

test("a lookup that never calls getSecret performs ZERO password reads", async () => {
  const s = spyRun((a) => (a.includes("-w") ? "hunter2\n" : ATTRS));
  const cred = await keychainLookup("mybank", { run: s.run });
  expect(cred?.username).toBe("alice");
  expect(cred?.origin).toBe("https://auth.mybank.com");
  expect(s.pwReads()).toBe(0); // list_credentials / origin_mismatch / user_denied paths
});

test("the password read happens exactly once, and only when getSecret() is called", async () => {
  const s = spyRun((a) => (a.includes("-w") ? "hunter2\n" : ATTRS));
  const cred = await keychainLookup("mybank", { run: s.run });
  expect(s.pwReads()).toBe(0);
  expect(cred!.getSecret()).toBe("hunter2");
  expect(s.pwReads()).toBe(1);
});

test("a genuine keychain miss is still a miss, with no password read", async () => {
  const s = spyRun(() => { throw notFound(); });
  expect(await keychainLookup("mybank", { run: s.run })).toBe(null);
  expect(s.pwReads()).toBe(0);
});

test("an entry that vanishes between lookup and getSecret is a fault, not an empty secret", async () => {
  const s = spyRun((a) => { if (a.includes("-w")) throw notFound(); return ATTRS; });
  const cred = await keychainLookup("mybank", { run: s.run });
  let err: any;
  try { cred!.getSecret(); } catch (e) { err = e; }
  expect(err).toBeInstanceOf(CdpError);
  expect(err.code).toBe("vault_error");
});

test("a denied password read throws vault_locked and returns no string", async () => {
  const s = spyRun((a) => { if (a.includes("-w")) throw denied(); return ATTRS; });
  const cred = await keychainLookup("mybank", { run: s.run });
  let err: any;
  try { cred!.getSecret(); } catch (e) { err = e; }
  expect(err?.code).toBe("vault_locked");
});

// ── Finding 3: a TOTP vault FAULT is not a missing seed ─────────────────────

test("keychainHasTotp: absent seed is false, present seed is true", () => {
  expect(keychainHasTotp("mybank", { run: () => { throw notFound(); } })).toBe(false);
  expect(keychainHasTotp("mybank", { run: () => "attrs" })).toBe(true);
});

test("keychainHasTotp THROWS vault_locked on a denied keychain — never has_totp:false", () => {
  let err: any;
  try { keychainHasTotp("mybank", { run: () => { throw denied(); } }); } catch (e) { err = e; }
  expect(err).toBeInstanceOf(CdpError);
  expect(err.code).toBe("vault_locked");
});

test("keychainTotpSeed: absent seed is null, present seed is trimmed", () => {
  expect(keychainTotpSeed("mybank", { run: () => { throw notFound(); } })).toBe(null);
  expect(keychainTotpSeed("mybank", { run: () => "JBSWY3DPEHPK3PXP\n" })).toBe("JBSWY3DPEHPK3PXP");
  expect(keychainTotpSeed("mybank", { run: () => "  \n" })).toBe(null); // empty entry is a miss
});

test("keychainTotpSeed THROWS vault_locked on a denied keychain — never no_totp", () => {
  let err: any;
  try { keychainTotpSeed("mybank", { run: () => { throw denied(); } }); } catch (e) { err = e; }
  expect(err).toBeInstanceOf(CdpError);
  expect(err.code).toBe("vault_locked");
});
