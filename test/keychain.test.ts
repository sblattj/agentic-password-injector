import { expect, test } from "bun:test";
import { isItemNotFound, parseAcct, parseComment } from "../src/vault/keychain.ts";
test("parseAcct pulls the account attribute from security -g output", () => {
  const out = 'keychain: "/Users/x/Library/Keychains/login.keychain-db"\n"acct"<blob>="alice@example.com"\n"svce"<blob>="apinj:mybank"';
  expect(parseAcct(out)).toBe("alice@example.com");
});
test("parseAcct returns null when absent", () => expect(parseAcct("nope")).toBe(null));

// ── Origin binding (fix round 1, finding 5) ─────────────────────────────────

const icmt = (v: string) => `"acct"<blob>="alice"\n"icmt"<blob>="${v}"\n"svce"<blob>="apinj:mybank"`;

test("parseComment reads the bound origin from the comment attribute", () => {
  expect(parseComment(icmt("https://auth.mybank.com"))).toEqual({
    origin: "https://auth.mybank.com", flags: {},
  });
});

test("parseComment returns empty when the entry has no comment", () => {
  expect(parseComment('"acct"<blob>="alice"\n"icmt"<blob>=<NULL>')).toEqual({ origin: "", flags: {} });
  expect(parseComment('"acct"<blob>="alice"')).toEqual({ origin: "", flags: {} });
});

// ── Named secrets: capability flags in the same comment attribute ────────────
//
// The bare-origin form is what every existing entry uses, so it must keep
// parsing exactly as before or the flags feature breaks every credential in the
// vault. The flags are strictly additive.

test("parseComment reads sel/kind flags alongside the origin", () => {
  expect(parseComment(icmt("https://www.experian.com sel=allow kind=text"))).toEqual({
    origin: "https://www.experian.com",
    flags: { sel: "allow", kind: "text" },
  });
});

test("parseComment does not care about flag ORDER, or about extra whitespace", () => {
  const a = parseComment(icmt("kind=text sel=allow https://www.experian.com"));
  const b = parseComment(icmt("https://www.experian.com   kind=text\tsel=allow"));
  expect(a).toEqual({ origin: "https://www.experian.com", flags: { sel: "allow", kind: "text" } });
  expect(b).toEqual(a);
});

test("parseComment IGNORES an unknown flag rather than throwing", () => {
  // A typo or a newer writer must not brick an otherwise valid credential.
  const p = parseComment(icmt("https://x.com sel=allow wat=1 kind=text"));
  expect(p.origin).toBe("https://x.com");
  expect(p.flags.sel).toBe("allow");
  expect(p.flags.kind).toBe("text");
  expect(p.flags.wat).toBe("1");
});

test("parseComment: a URL is never mistaken for a flag, even with a query string", () => {
  expect(parseComment(icmt("https://x.com/login?a=b")).origin).toBe("https://x.com/login?a=b");
  expect(parseComment(icmt("https://x.com:8443")).origin).toBe("https://x.com:8443");
  expect(parseComment(icmt("https://x.com/login?a=b")).flags).toEqual({});
});

test("parseComment: flags with NO origin yield origin '' — sel=allow is not a binding", () => {
  // Fails closed downstream with no_origin_binding rather than letting a flag
  // token become the value the gate compares the tab against.
  expect(parseComment(icmt("sel=allow kind=text"))).toEqual({
    origin: "", flags: { sel: "allow", kind: "text" },
  });
});

test("parseComment: a SECOND bare token cannot replace the binding", () => {
  expect(parseComment(icmt("https://real.com https://evil.com")).origin).toBe("https://real.com");
});

test("parseComment: flag values are case-preserved but keys are not — deny stays deny", () => {
  // `sel=ALLOW` is not `sel=allow`; the call site compares the exact string, so
  // anything that is not the literal grant is a denial.
  expect(parseComment(icmt("https://x.com sel=ALLOW")).flags.sel).toBe("ALLOW");
  expect(parseComment(icmt("https://x.com SEL=allow")).flags.sel).toBe("allow");
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

import { keychainLookup, keychainHasTotp, keychainSecret, keychainTotpSeed } from "../src/vault/keychain.ts";
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

// ── Named secrets: keychainSecret ────────────────────────────────────────────

const SECRET_ATTRS =
  '"icmt"<blob>="https://www.experian.com sel=allow kind=text"\n"svce"<blob>="apinj:ssn-full"';

test("keychainSecret returns the origin and the flags, and reads NO plaintext", async () => {
  const s = spyRun((a) => (a.includes("-w") ? "123456789\n" : SECRET_ATTRS));
  const e = await keychainSecret("ssn-full", { run: s.run });
  expect(e?.origin).toBe("https://www.experian.com");
  expect(e?.flags).toEqual({ sel: "allow", kind: "text" });
  expect(s.pwReads()).toBe(0); // I2: lazy, exactly like a credential
});

test("keychainSecret reads the plaintext exactly once, only when asked", async () => {
  const s = spyRun((a) => (a.includes("-w") ? "123456789\n" : SECRET_ATTRS));
  const e = await keychainSecret("ssn-full", { run: s.run });
  expect(s.pwReads()).toBe(0);
  expect(e!.getSecret()).toBe("123456789");
  expect(s.pwReads()).toBe(1);
});

test("keychainSecret needs NO account attribute — a secret has no username", async () => {
  // keychainLookup treats a missing `acct` as a misconfigured entry; a named
  // secret legitimately has none, so demanding one would make every entry carry
  // a decorative -a.
  const s = spyRun((a) => (a.includes("-w") ? "123456789\n" : '"icmt"<blob>="https://x.com"'));
  const e = await keychainSecret("ssn-full", { run: s.run });
  expect(e?.origin).toBe("https://x.com");
  expect(e?.flags).toEqual({});
});

test("keychainSecret: a genuine miss is null, with no plaintext read", async () => {
  const s = spyRun(() => { throw notFound(); });
  expect(await keychainSecret("nope", { run: s.run })).toBe(null);
  expect(s.pwReads()).toBe(0);
});

test("keychainSecret: a DENIED keychain throws vault_locked — never reads as a miss", async () => {
  let err: any;
  try { await keychainSecret("ssn-full", { run: () => { throw denied(); } }); } catch (e) { err = e; }
  expect(err).toBeInstanceOf(CdpError);
  expect(err.code).toBe("vault_locked");
});

test("keychainSecret: an entry that vanishes between lookup and read is a fault", async () => {
  const s = spyRun((a) => { if (a.includes("-w")) throw notFound(); return SECRET_ATTRS; });
  const e = await keychainSecret("ssn-full", { run: s.run });
  let err: any;
  try { e!.getSecret(); } catch (x) { err = x; }
  expect(err?.code).toBe("vault_error");
});

test("keychainSecret looks under apinj:<name>, the same namespace as a credential", async () => {
  const s = spyRun(() => SECRET_ATTRS);
  await keychainSecret("ssn-full", { run: s.run });
  expect(s.calls[0]).toContain("apinj:ssn-full");
});
