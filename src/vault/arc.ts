import { Database } from "bun:sqlite";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";
import { decryptChromium } from "./decrypt.ts";
import { CdpError } from "../cdp.ts";
import { PUBLIC_SUFFIXES as SUFFIXES } from "../domain.ts";
export interface Cred { origin: string; username: string; getSecret: () => string; }
function keychainSecret(): string {
  try { return execFileSync("security", ["find-generic-password", "-s", "Arc Safe Storage", "-w"], { encoding: "utf8" }).trim(); }
  catch { throw new CdpError("vault_locked", "Arc Safe Storage key unreadable — grant Keychain access"); }
}
// Multi-label public suffixes, single-sourced in src/domain.ts (the list itself
// had drifted 78 entries behind the entry-point copy). Not the full PSL — the job
// here is to refuse a KEY THAT MATCHES EVERYTHING, not to be authoritative about
// registrability. `tools.ts:isValidDomain` is the first guard at the entry point;
// this is the second, INDEPENDENT one, and neither is allowed to be the only one.

const LABEL = /^(?:xn--)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

function labelsOf(s: string): string[] | null {
  const parts = s.split(".");
  return parts.every((p) => LABEL.test(p)) ? parts : null;
}

/**
 * Is `d` a plausible REGISTRABLE domain to look credentials up by?
 *
 * A bare TLD ("com") or a public suffix ("co.uk") is a key that matches every
 * saved login, which turns a metadata-only lookup into a bank-enumeration sweep.
 * Refuse both, and refuse anything that is not a syntactically clean hostname.
 */
export function isRegistrableDomain(raw: string): boolean {
  const d = raw.trim().toLowerCase();
  if (!d || d.length > 253) return false;
  const labels = labelsOf(d);
  if (!labels || labels.length < 2) return false;
  return !SUFFIXES.has(d);
}

/**
 * Host match on LABEL BOUNDARIES, never on raw suffix text. `endsWith("." + d)`
 * alone accepts nothing dangerous by itself, but `endsWith(d)` sloppiness in the
 * same shape is what makes `evilmybank.com` look like `mybank.com`, and an
 * unvalidated `d` makes `com` match the whole vault. Both are closed here.
 */
export function hostMatches(host: string, domain: string): boolean {
  const d = domain.trim().toLowerCase().replace(/\.$/, "");
  if (!isRegistrableDomain(d)) return false;
  const h = host.trim().toLowerCase().replace(/\.$/, "");
  if (!labelsOf(h)) return false;
  return h === d || h.endsWith("." + d);
}
/**
 * "Arc is not installed / has no login DB" is a MISS. "macOS refused to let us
 * read it" is a FAULT. Collapsing the second into the first reports a locked
 * vault as `not_found`, which reads like "you have no such credential" — the
 * bad-credential-looking shape invariant #3 forbids.
 *
 * Anything unrecognised is treated as denied: a false `vault_locked` is a
 * confusing message, a false `not_found` sends the user hunting for a
 * credential they already have.
 */
export function classifyCopyError(e: unknown): "missing" | "denied" {
  const err = e as { code?: string; message?: string };
  if (err?.code === "ENOENT") return "missing";
  return "denied";
}

export interface ArcIo { copy?: (src: string, dest: string) => void }

export async function arcLookup(domain: string, io: ArcIo = {}, opts: { name?: string } = {}): Promise<Cred | null> {
  const copy = io.copy ?? copyFileSync;
  const src = join(homedir(), "Library/Application Support/Arc/User Data/Default/Login Data");
  const dir = mkdtempSync(join(tmpdir(), "apinj-"));
  const tmp = join(dir, "Login Data");
  try {
    try { copy(src, tmp); }
    catch (e) {
      if (classifyCopyError(e) === "missing") return null; // genuine miss
      throw new CdpError("vault_locked", "Arc Login Data unreadable — grant Full Disk Access");
    }
    const db = new Database(tmp, { readonly: true });
    let rows: { origin_url: string; username_value: string; password_value: Uint8Array }[];
    try {
      rows = db.query("SELECT origin_url, username_value, password_value FROM logins").all() as { origin_url: string; username_value: string; password_value: Uint8Array }[];
    } finally {
      db.close();
    }
    // `name`, when supplied, SELECTS: only a row whose username is that name may
    // be returned. Taking the first domain hit instead would hand back a
    // different account than the caller asked to log into.
    const row = rows.find((r) => {
      if (opts.name !== undefined && r.username_value !== opts.name) return false;
      try { return hostMatches(new URL(r.origin_url).hostname, domain); } catch { return false; }
    });
    if (!row) return null;
    return { origin: new URL(row.origin_url).origin, username: row.username_value, getSecret: () => decryptChromium(Buffer.from(row.password_value), keychainSecret()) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
