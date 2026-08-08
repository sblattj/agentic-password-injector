import { expect, test } from "bun:test";
import { pbkdf2Key, decryptCBC, encryptCBCForTest } from "../src/vault/decrypt.ts";
// Chromium mac CBC: PBKDF2-SHA1(secret,'saltysalt',1003,16), AES-128-CBC, IV=16 spaces, 'v10' prefix.
test("pbkdf2Key derives a 16-byte key", () => {
  expect(pbkdf2Key("peanuts").length).toBe(16);
});
test("decryptCBC round-trips a known vector", () => {
  const key = pbkdf2Key("peanuts");
  const ct = encryptCBCForTest(key, "hunter2");        // helper used ONLY in tests
  expect(decryptCBC(ct, key)).toBe("hunter2");
});

// ── Fix round 3 (vault seat), finding 5: a wrong key must not yield garbage ──

import { createDecipheriv } from "node:crypto";
import { decryptChromium, isPlausibleSecret } from "../src/vault/decrypt.ts";
import { CdpError } from "../src/cdp.ts";

const IV16 = Buffer.alloc(16, 0x20);

/** Raw CBC decrypt with padding validation only — what the code did BEFORE the
 *  plausibility check. Used to FIND a wrong key that survives padding (~1/256). */
function rawCBC(blob: Buffer, key: Buffer): string | null {
  const d = createDecipheriv("aes-128-cbc", key, IV16); d.setAutoPadding(true);
  try { return Buffer.concat([d.update(blob.subarray(3)), d.final()]).toString("utf8"); }
  catch { return null; }
}

test("isPlausibleSecret accepts real passwords and rejects binary garbage", () => {
  expect(isPlausibleSecret(Buffer.from("hunter2", "utf8"))).toBe(true);
  expect(isPlausibleSecret(Buffer.from("pä$$wörd — ünicode ok", "utf8"))).toBe(true);
  expect(isPlausibleSecret(Buffer.from("", "utf8"))).toBe(true); // empty is odd, not evidence of a wrong key
  expect(isPlausibleSecret(Buffer.from([0x68, 0x00, 0x69]))).toBe(false);      // NUL
  expect(isPlausibleSecret(Buffer.from([0x68, 0x07, 0x69]))).toBe(false);      // control
  expect(isPlausibleSecret(Buffer.from([0xff, 0xfe, 0xfd, 0xfc]))).toBe(false); // invalid UTF-8
});

test("a WRONG key that survives PKCS7 padding yields decrypt_failed, not garbage", () => {
  const good = pbkdf2Key("peanuts");
  const ct = encryptCBCForTest(good, "hunter2");
  // Deterministic search for a wrong key whose padding happens to validate.
  let wrong: Buffer | null = null, garbage = "";
  for (let i = 0; i < 20000 && !wrong; i++) {
    const k = pbkdf2Key(`wrong-${i}`);
    const out = rawCBC(ct, k);
    if (out !== null && !isPlausibleSecret(Buffer.from(out, "utf8"))) { wrong = k; garbage = out; }
  }
  expect(wrong).not.toBe(null);      // the ~1/256 padding collision is real
  expect(garbage).not.toBe("hunter2");
  let err: any;
  try { decryptCBC(ct, wrong!); } catch (e) { err = e; }
  expect(err).toBeInstanceOf(CdpError);
  expect(err.code).toBe("decrypt_failed");
  expect(err.message).not.toContain(garbage); // the plaintext never reaches the message
});

test("decryptChromium still returns a correct decrypt of a known fixture", () => {
  const blob = encryptCBCForTest(pbkdf2Key("peanuts"), "hunter2");
  expect(decryptChromium(blob, "peanuts")).toBe("hunter2");
});

test("decryptChromium on a wrong keychain secret fails closed with decrypt_failed", () => {
  const blob = encryptCBCForTest(pbkdf2Key("peanuts"), "hunter2");
  let err: any;
  try { decryptChromium(blob, "not-the-key"); } catch (e) { err = e; }
  expect(err?.code).toBe("decrypt_failed");
});
