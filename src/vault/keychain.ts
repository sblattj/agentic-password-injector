import { execFileSync } from "node:child_process";
import type { Cred } from "./arc.ts";
import { CdpError } from "../cdp.ts";

// Keychain-backed credentials must carry the origin they are bound to, stored in
// the generic-password *comment* attribute (`-j`). Without it the origin gate has
// nothing to compare against and the caller-supplied domain would become the
// binding — which is no binding at all. See docs/keychain-setup.md.
//
//   security add-generic-password -s 'apinj:mybank' -a 'alice' \
//     -w 'password' -j 'https://auth.mybank.com'
//
// The same comment attribute also carries the per-entry capability flags a named
// secret needs (`sel=`, `kind=`), so that widening what may be done with a value
// is a decision a human makes with `security`, not one the caller makes at call
// time. See `parseComment` and `keychainSecret` below.

export function parseAcct(securityGOutput: string): string | null {
  const m = securityGOutput.match(/"acct"<blob>="([^"]*)"/);
  return m ? m[1] : null;
}

/**
 * Per-entry capability flags, carried in the comment attribute alongside the
 * origin. Everything not listed here parses and is ignored — an unknown flag is
 * a typo or a newer writer, and throwing would make one bad character brick an
 * otherwise valid credential.
 */
export interface CommentFlags {
  /** `sel=allow` lets a CALLER supply the CSS selector. Absent = deny. */
  sel?: string;
  /** `kind=text` lets the secret land in a non-password input. Absent = deny. */
  kind?: string;
  [k: string]: string | undefined;
}

// A flag token, `key=value`. An origin never matches it: `https://x.com` stops at
// the colon, and a URL carrying a query string still starts with a scheme.
const FLAG_TOKEN = /^([a-z][a-z0-9_-]*)=(.*)$/i;

/**
 * The entry's comment attribute, split into the bound origin and any flags.
 *
 *   -j 'https://forms.example.com'                    → { origin, flags: {} }
 *   -j 'https://forms.example.com sel=allow kind=text' → { origin, flags: {…} }
 *
 * The bare-origin form is the one every existing entry uses and MUST keep
 * parsing exactly as before; the flags are additive. Order does not matter, and
 * a comment that carries flags but no origin yields origin "" — which fails
 * closed at the call site with `no_origin_binding` rather than letting
 * `sel=allow` be mistaken for a binding.
 */
export function parseComment(securityGOutput: string): { origin: string; flags: CommentFlags } {
  const m = securityGOutput.match(/"icmt"<blob>="([^"]*)"/);
  const flags: CommentFlags = {};
  let origin = "";
  for (const tok of (m ? m[1] : "").split(/\s+/)) {
    if (!tok) continue;
    const f = tok.match(FLAG_TOKEN);
    if (f) { flags[f[1].toLowerCase()] = f[2]; continue; }
    // First bare token is the origin. A SECOND one is neither an origin nor a
    // flag, so it is dropped rather than allowed to replace the binding.
    if (!origin) origin = tok;
  }
  return { origin, flags };
}

/**
 * True only for "no such item". Anything else — access denied, user interaction
 * not allowed, a locked keychain — is a VAULT ERROR and must never be reported as
 * a missing credential (that is the bad-credential-looking shape invariant #3
 * forbids). `security` exits 44 for errSecItemNotFound.
 */
export function isItemNotFound(e: unknown): boolean {
  const err = e as { status?: number; stderr?: unknown };
  if (err?.status === 44) return true;
  if (typeof err?.status === "number") return false;
  return /could not be found/i.test(String(err?.stderr ?? ""));
}

/**
 * Runs `security`, returning null for a genuine miss and THROWING for a vault
 * fault. The thrown message is fixed text: `-g` prints the secret on stderr, so
 * the captured stderr must never reach an error message or a log.
 */
export type SecurityRunner = (args: string[]) => string;
export interface KeychainIo { run?: SecurityRunner }

const realRun: SecurityRunner = (args) =>
  execFileSync("security", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

function securityRun(args: string[], run: SecurityRunner = realRun): string | null {
  try {
    return run(args);
  } catch (e) {
    if (isItemNotFound(e)) return null;
    throw new CdpError("vault_locked", "keychain access failed");
  }
}

function svc(name: string) { return `apinj:${name}`; }

/**
 * SECURITY (I2): the plaintext is read LAZILY.
 *
 * Lookup reads ATTRIBUTES only (`-g`); the password read (`-w`) happens inside
 * `getSecret()`, i.e. only on a path that has already passed the origin gate and
 * the consent dialog. Reading it at lookup time pulled the password into process
 * memory for `list_credentials` (documented metadata-only) and for every
 * origin_mismatch / user_denied abort — decrypting a secret before the user was
 * even asked. The Arc backend was already lazy; this makes the two match.
 */
export async function keychainLookup(name: string, io: KeychainIo = {}): Promise<Cred | null> {
  const attrs = securityRun(["find-generic-password", "-s", svc(name), "-g"], io.run);
  if (attrs === null) return null;
  const acct = parseAcct(attrs);
  // M6: the entry EXISTS but carries no account attribute. That is a
  // misconfigured entry, not an absent one, and reporting `not_found` sends the
  // user hunting for a credential they already created. Surface it as a fault.
  if (!acct) throw new CdpError("vault_error", "keychain entry is missing its account attribute");
  // origin may be "" — the tools layer fails closed on that rather than guessing.
  return {
    origin: parseComment(attrs).origin,
    username: acct,
    getSecret: () => {
      const w = securityRun(["find-generic-password", "-s", svc(name), "-w"], io.run);
      // The attribute read succeeded moments ago, so a miss here is not "no such
      // credential" — the entry was deleted or the read was refused mid-flight.
      if (w === null) throw new CdpError("vault_error", "keychain entry vanished between lookup and read");
      return w.trim();
    },
  };
}

/**
 * A NAMED SECRET: an SSN, a freeze PIN, an account number — a value that is not
 * a login credential and has no username to show in a consent dialog.
 *
 * Same `apinj:<name>` namespace as a credential, deliberately: one entry, one
 * origin binding, one place to look. The differences from `keychainLookup`:
 *
 * - No account attribute is required. A secret has no username, and demanding
 *   one would make every entry carry a decorative `-a`.
 * - The comment's FLAGS are returned. They are the only thing that can widen
 *   what `fill_secret` is allowed to do with the value, and they are set by a
 *   human at storage time — never by the caller at call time.
 *
 * The plaintext read stays LAZY (I2), for the same reason it is lazy for a
 * credential: the origin gate and the consent dialog both run before it, and an
 * `origin_mismatch` must not have decrypted anything.
 */
export interface SecretEntry {
  origin: string;
  flags: CommentFlags;
  getSecret: () => string;
}

export async function keychainSecret(name: string, io: KeychainIo = {}): Promise<SecretEntry | null> {
  const attrs = securityRun(["find-generic-password", "-s", svc(name), "-g"], io.run);
  if (attrs === null) return null;
  const { origin, flags } = parseComment(attrs);
  return {
    origin,
    flags,
    getSecret: () => {
      const w = securityRun(["find-generic-password", "-s", svc(name), "-w"], io.run);
      if (w === null) throw new CdpError("vault_error", "keychain entry vanished between lookup and read");
      return w.trim();
    },
  };
}

// ── Writing a credential (`save_credential`) ─────────────────────────────────
//
// The password must never appear on argv: any local user can read another
// process's arguments with `ps`. So the write goes through `security -i`, which
// reads commands from STDIN, over a pipe.
//
// `security -i` is LINE-oriented and has its own quoting, which is why every
// value is checked here, not just at the tool entry point (the same
// belt-and-braces split as `isValidSecretName` / `safeSecretName`):
//
// - A newline or carriage return would END the command and turn the rest of the
//   value into a SECOND command. Every control character is refused.
// - Inside double quotes, `\"` is a quote and `\\` is a backslash (probed on
//   macOS: `a\b`, `a\\b`, `ab\`, `a\"b`, `it's`, `$HOME`, `{}[]|&;#!*?~%^`
//   all round-trip byte for byte).
// - The line buffer is about 4 KB. A 4000-char password was TRUNCATED to 3998
//   chars and still stored, with exit 1. `SAVE_PASSWORD_MAX` keeps the whole
//   escaped line far below that.
// - Tab and non-ASCII bytes are stored correctly, but `find-generic-password -w`
//   then prints the value as HEX, and `getSecret` above would type the hex. A
//   leading or trailing space would be lost to `getSecret`'s trim. Those values
//   are refused rather than saved in a form `login` would mangle.
// - A username with `"`, `\` or non-ASCII is stored, but `parseAcct` cannot read
//   it back (it returns a truncated name or null), so it is refused too.

/** Longest password `save_credential` accepts. Escaped, it is at most 2048 chars. */
export const SAVE_PASSWORD_MAX = 1024;
export const SAVE_USERNAME_MAX = 128;

/** Printable ASCII, no control characters. */
const PRINTABLE_ASCII = /^[\x20-\x7e]+$/;

/**
 * True when `security -i` can carry the password AND the existing read path
 * (`getSecret`) returns it unchanged. The reason it fails is never reported:
 * "too long" or "has a tab" is a fact about a secret the model must not learn.
 */
export function isStorablePassword(pw: string): boolean {
  if (typeof pw !== "string" || pw.length === 0 || pw.length > SAVE_PASSWORD_MAX) return false;
  if (!PRINTABLE_ASCII.test(pw)) return false;
  return pw === pw.trim();
}

/** Printable ASCII without `"` or `\`, 1 to 128 chars: what `parseAcct` reads back intact. */
export function isStorableUsername(u: string): boolean {
  if (typeof u !== "string" || u.length === 0 || u.length > SAVE_USERNAME_MAX) return false;
  return PRINTABLE_ASCII.test(u) && !/["\\]/.test(u);
}

/**
 * One double-quoted `security -i` argument. Throws (fixed text, no value) on a
 * control character or a non-ASCII byte, so a value that could split the
 * command line never reaches the pipe, whatever the caller validated.
 */
export function securityQuote(v: string): string {
  if (!PRINTABLE_ASCII.test(v)) throw new CdpError("vault_error", "value cannot be written safely");
  return `"${v.replace(/[\\"]/g, "\\$&")}"`;
}

/** Runs `security -i` with `input` on stdin. Output and stderr are discarded by callers. */
export type SecurityStdinRunner = (input: string) => string;

const realRunStdin: SecurityStdinRunner = (input) =>
  execFileSync("security", ["-i"], { input, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });

export interface KeychainWriteIo { run?: SecurityRunner; runStdin?: SecurityStdinRunner }

/**
 * Whether `apinj:<name>` exists, and under which account. ATTRIBUTES ONLY: no
 * `-g` (which prints the secret on stderr) and no `-w`. Returns null on a miss
 * and throws `vault_locked` on a fault, like every other read here.
 */
export function keychainExisting(name: string, io: KeychainWriteIo = {}): { account: string | null } | null {
  const attrs = securityRun(["find-generic-password", "-s", svc(name)], io.run);
  return attrs === null ? null : { account: parseAcct(attrs) };
}

export interface NewCredential { name: string; origin: string; username: string; password: string }

/**
 * Writes `apinj:<name>` with the account, the bound origin in the comment, and
 * the password, all over stdin. `replace` names the account of the entry being
 * replaced (from `keychainExisting`); omit it for a new entry.
 *
 * Replacing is NOT just `-U`: `-U` matches on service AND account, so with a
 * different username it adds a SECOND item under `apinj:<name>` and the stale
 * one keeps winning lookups (probed). So:
 * - same account: `add-generic-password -U` updates the password and comment in place;
 * - different account: add the new item first, then delete the old one by
 *   account, so a failed add never loses the credential that was there.
 *
 * Every failure throws `vault_error` with fixed text. Nothing from `security`'s
 * output, and nothing of the password, reaches an error.
 */
export function keychainStore(c: NewCredential, opts: { replace?: { account: string | null } } = {}, io: KeychainWriteIo = {}): void {
  if (!isStorablePassword(c.password) || !isStorableUsername(c.username)) {
    throw new CdpError("vault_error", "value cannot be written safely");
  }
  const runStdin = io.runStdin ?? realRunStdin;
  const run = io.run ?? realRun;
  const prev = opts.replace;
  const inPlace = prev !== undefined && prev.account === c.username;
  const line = [
    "add-generic-password",
    ...(inPlace ? ["-U"] : []),
    "-s", securityQuote(svc(c.name)),
    "-a", securityQuote(c.username),
    "-j", securityQuote(c.origin),
    "-w", securityQuote(c.password),
  ].join(" ") + "\n";
  const del = (args: string[]) => {
    try { run(args); }
    catch (e) { if (!isItemNotFound(e)) throw new CdpError("vault_error", "old keychain entry could not be removed"); }
  };
  // An old entry with NO account attribute is already unusable (`keychainLookup`
  // rejects it) and cannot be selected by `-a`, so it is removed BEFORE the add:
  // deleting by service alone afterwards could hit the new item instead.
  if (prev !== undefined && !inPlace && !prev.account) del(["delete-generic-password", "-s", svc(c.name)]);
  try {
    runStdin(line);
  } catch {
    throw new CdpError("vault_error", "keychain write failed");
  }
  if (prev !== undefined && !inPlace && prev.account) {
    del(["delete-generic-password", "-s", svc(c.name), "-a", prev.account]);
  }
}

function totpSvc(name: string) { return `apinj-totp:${name}`; }

/**
 * Fault vs miss (I1): these two used to be bare catch-alls, so a LOCKED keychain
 * or a denied ACL reported `has_totp:false` / `no_totp` — "you never configured
 * TOTP" — for a seed that exists. Both now route through `securityRun`, which
 * returns null ONLY for errSecItemNotFound and throws `vault_locked` otherwise.
 */
export function keychainHasTotp(name: string, io: KeychainIo = {}): boolean {
  return securityRun(["find-generic-password", "-s", totpSvc(name)], io.run) !== null;
}

/** Reads the base32 TOTP seed. NEVER let the return value cross a tool boundary. */
export function keychainTotpSeed(name: string, io: KeychainIo = {}): string | null {
  const w = securityRun(["find-generic-password", "-s", totpSvc(name), "-w"], io.run);
  return w === null ? null : (w.trim() || null);
}
