import { execFileSync } from "node:child_process";
import { CdpError } from "../cdp.ts";
import { isItemNotFound, parseAcct, parseComment, securityQuote, type SecurityRunner, type SecurityStdinRunner } from "./keychain.ts";

// ── Agent passkeys in the Keychain ───────────────────────────────────────────
//
// One generic-password item per passkey, service `apinj-passkey:<name>`:
//   account (-a) = the WebAuthn rpId (metadata, shown by `security`)
//   comment (-j) = the BOUND origin, the same binding every other entry uses
//   password (-w) = a JSON record holding the PKCS#8 private key and the rest
//
// The record is written over `security -i` on stdin, never argv, exactly like
// `keychainStore`. It is read LAZILY: lookup reads attributes only, and the
// private key is decrypted inside `getRecord()`, which the tools layer calls
// only after the origin gate and consent have passed.

export interface PasskeyRecord {
  /** base64 credential id, as `WebAuthn.getCredentials` returns it. */
  credentialId: string;
  rpId: string;
  /** base64 PKCS#8 private key. NEVER crosses a tool boundary. */
  privateKey: string;
  /** base64 user handle, or "" when the site set none. */
  userHandle: string;
  signCount: number;
  backupEligibility?: boolean;
  backupState?: boolean;
}

export interface PasskeyEntry {
  origin: string;
  rpId: string;
  getRecord: () => PasskeyRecord;
}

export interface PasskeyIo { run?: SecurityRunner; runStdin?: SecurityStdinRunner }

const realRun: SecurityRunner = (args) =>
  execFileSync("security", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const realRunStdin: SecurityStdinRunner = (input) =>
  execFileSync("security", ["-i"], { input, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });

export function passkeySvc(name: string) { return `apinj-passkey:${name}`; }

function run(args: string[], r: SecurityRunner): string | null {
  try { return r(args); } catch (e) {
    if (isItemNotFound(e)) return null;
    throw new CdpError("vault_locked", "keychain access failed");
  }
}

const B64 = /^[A-Za-z0-9+/]*={0,2}$/;
const RPID = /^[a-z0-9.-]{1,253}$/;

/** Shape check on a record, both before writing and after reading. Never says which field failed. */
export function isValidRecord(r: unknown): r is PasskeyRecord {
  const x = r as PasskeyRecord;
  return !!x && typeof x === "object" &&
    typeof x.credentialId === "string" && x.credentialId.length > 0 && x.credentialId.length <= 1024 && B64.test(x.credentialId) &&
    typeof x.privateKey === "string" && x.privateKey.length > 0 && x.privateKey.length <= 2048 && B64.test(x.privateKey) &&
    typeof x.userHandle === "string" && x.userHandle.length <= 512 && B64.test(x.userHandle) &&
    typeof x.rpId === "string" && RPID.test(x.rpId) &&
    Number.isInteger(x.signCount) && x.signCount >= 0 && x.signCount <= 0xffffffff &&
    (x.backupEligibility === undefined || typeof x.backupEligibility === "boolean") &&
    (x.backupState === undefined || typeof x.backupState === "boolean");
}

/** Only the fields we know, in a fixed order: nothing extra from CDP is ever persisted. */
export function serializeRecord(r: PasskeyRecord): string {
  return JSON.stringify({
    v: 1, credentialId: r.credentialId, rpId: r.rpId, privateKey: r.privateKey, userHandle: r.userHandle,
    signCount: r.signCount,
    ...(r.backupEligibility === undefined ? {} : { backupEligibility: r.backupEligibility }),
    ...(r.backupState === undefined ? {} : { backupState: r.backupState }),
  });
}

/** Attributes only. Null on a miss, throws `vault_locked` on a fault. */
export function passkeyLookup(name: string, io: PasskeyIo = {}): PasskeyEntry | null {
  const r = io.run ?? realRun;
  const attrs = run(["find-generic-password", "-s", passkeySvc(name)], r);
  if (attrs === null) return null;
  return {
    origin: parseComment(attrs).origin,
    rpId: parseAcct(attrs) ?? "",
    getRecord: () => {
      const w = run(["find-generic-password", "-s", passkeySvc(name), "-w"], r);
      if (w === null) throw new CdpError("vault_error", "keychain entry vanished between lookup and read");
      let rec: unknown;
      try { rec = JSON.parse(w.trim()); } catch { throw new CdpError("vault_error", "passkey record unreadable"); }
      if (!isValidRecord(rec)) throw new CdpError("vault_error", "passkey record unreadable");
      // Re-derive through the serializer so only known fields come back.
      const { v: _v, ...clean } = JSON.parse(serializeRecord(rec)) as PasskeyRecord & { v: number };
      return clean;
    },
  };
}

/**
 * Writes (or, with `replace`, updates in place) `apinj-passkey:<name>`.
 * The account is the rpId, so an update for the same rpId is `-U` in place; a
 * replace across rpIds deletes the old item after the new one is written.
 * Every failure is `vault_error` with fixed text.
 */
export function passkeyStore(
  name: string, origin: string, rec: PasskeyRecord,
  opts: { replace?: { rpId: string } } = {}, io: PasskeyIo = {},
): void {
  if (!isValidRecord(rec)) throw new CdpError("vault_error", "value cannot be written safely");
  const runStdin = io.runStdin ?? realRunStdin;
  const r = io.run ?? realRun;
  const prev = opts.replace;
  const inPlace = prev !== undefined && prev.rpId === rec.rpId;
  const line = [
    "add-generic-password",
    ...(inPlace ? ["-U"] : []),
    "-s", securityQuote(passkeySvc(name)),
    "-a", securityQuote(rec.rpId),
    "-j", securityQuote(origin),
    "-w", securityQuote(serializeRecord(rec)),
  ].join(" ") + "\n";
  // The `security -i` line buffer is ~4 KB; a truncated record would be stored
  // with exit 1 and read back as garbage. A P-256 record is ~400 chars.
  if (line.length > 3500) throw new CdpError("vault_error", "value cannot be written safely");
  try { runStdin(line); } catch { throw new CdpError("vault_error", "keychain write failed"); }
  if (prev !== undefined && !inPlace && prev.rpId) {
    try { r(["delete-generic-password", "-s", passkeySvc(name), "-a", prev.rpId]); }
    catch (e) { if (!isItemNotFound(e)) throw new CdpError("vault_error", "old keychain entry could not be removed"); }
  }
}
