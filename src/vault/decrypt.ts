import { pbkdf2Sync, createDecipheriv, createCipheriv } from "node:crypto";
import { CdpError } from "../cdp.ts";
const SALT = "saltysalt", IV16 = Buffer.alloc(16, 0x20); // 16 spaces
export function pbkdf2Key(secret: string): Buffer { return pbkdf2Sync(secret, SALT, 1003, 16, "sha1"); }
/**
 * Is this decrypted buffer plausibly a stored credential?
 *
 * CBC has no authentication tag: a WRONG key still produces output whenever the
 * trailing bytes happen to form valid PKCS#7 padding, which is roughly 1 in 256.
 * Without this check that garbage is returned as the password and surfaces
 * downstream as "the site rejected my login" instead of a diagnosable
 * `decrypt_failed`.
 *
 * The predicate is deliberately conservative — it must never reject a real
 * password, including non-ASCII ones:
 *   - the bytes must be valid UTF-8 (round-trip, since `toString("utf8")`
 *     silently substitutes U+FFFD for invalid sequences), and
 *   - no C0/C1 control characters, DEL, or NUL — a saved password field cannot
 *     contain them, while random bytes contain one with overwhelming odds.
 * An EMPTY result is accepted: an empty stored value is odd but is not evidence
 * of a wrong key, and rejecting it would invent a new failure mode.
 */
export function isPlausibleSecret(buf: Buffer): boolean {
  const s = buf.toString("utf8");
  if (!Buffer.from(s, "utf8").equals(buf)) return false; // invalid UTF-8
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (c < 0x20 || c === 0x7f || (c >= 0x80 && c <= 0x9f)) return false;
  }
  return true;
}

/** Never let the implausible plaintext itself reach a message, a log, or a return. */
function plainOrFail(buf: Buffer, where: string): string {
  if (!isPlausibleSecret(buf)) throw new CdpError("decrypt_failed", `${where}: implausible plaintext`);
  return buf.toString("utf8");
}

export function decryptCBC(blob: Buffer, key: Buffer): string {
  const body = blob.subarray(3); // strip 'v10'
  const d = createDecipheriv("aes-128-cbc", key, IV16); d.setAutoPadding(true);
  let out: Buffer;
  try { out = Buffer.concat([d.update(body), d.final()]); }
  catch { throw new CdpError("decrypt_failed", "CBC"); }
  return plainOrFail(out, "CBC");
}
export function decryptGCM(blob: Buffer, key: Buffer): string {
  // v10/v11 GCM: [3-byte prefix][12-byte nonce][ciphertext][16-byte tag]
  const nonce = blob.subarray(3, 15), tag = blob.subarray(blob.length - 16), body = blob.subarray(15, blob.length - 16);
  const d = createDecipheriv("aes-256-gcm", key, nonce); d.setAuthTag(tag);
  let out: Buffer;
  // GCM authenticates, so a wrong key throws here; the plausibility check is kept
  // for symmetry and to catch a right-key/wrong-scheme decode.
  try { out = Buffer.concat([d.update(body), d.final()]); }
  catch { throw new CdpError("decrypt_failed", "GCM"); }
  return plainOrFail(out, "GCM");
}
export function decryptChromium(blob: Buffer, keychainSecret: string): string {
  const prefix = blob.subarray(0, 3).toString("latin1");
  if (prefix === "v10" || prefix === "v11") {
    // On macOS Arc uses the CBC scheme under a 'v10' tag; GCM ('v11', or 'v10' with a 32-byte key) is the newer path.
    // Try CBC first (mac-historical), fall back to GCM.
    try { return decryptCBC(blob, pbkdf2Key(keychainSecret)); }
    catch { return decryptGCM(blob, pbkdf2Sync(keychainSecret, SALT, 1003, 32, "sha1")); }
  }
  throw new CdpError("decrypt_failed", `unknown prefix ${prefix}`);
}
// test-only helper:
export function encryptCBCForTest(key: Buffer, plain: string): Buffer {
  const c = createCipheriv("aes-128-cbc", key, IV16);
  return Buffer.concat([Buffer.from("v10"), c.update(Buffer.from(plain, "utf8")), c.final()]);
}
