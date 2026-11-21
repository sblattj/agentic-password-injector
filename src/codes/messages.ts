// SMS source: macOS Messages `chat.db` (needs Full Disk Access for the host app).
// Opened read-only per fetch (not immutable, not copied: the newest rows live in
// the WAL). Nothing from a row is ever put in an error message.
import { Database } from "bun:sqlite";
import { homedir } from "node:os";
import { CdpError } from "../cdp.ts";
import type { CodeMessage, CodeSource } from "./types.ts";

const APPLE_EPOCH_S = 978307200;
const NSSTRING = new TextEncoder().encode("NSString");

function indexOf(hay: Uint8Array, needle: Uint8Array, from = 0): number {
  outer: for (let i = from; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

/** Pull the plain string out of an NSArchiver typedstream `attributedBody` blob. Total: null on anything odd. */
export function decodeAttributedBody(blob: Uint8Array): string | null {
  try {
    if (!blob || blob.length < 12) return null;
    let from = 0;
    while (true) {
      const at = indexOf(blob, NSSTRING, from);
      if (at < 0) return null;
      const start = at + NSSTRING.length;
      // a few header bytes, then the 0x2B ('+') marker
      let m = -1;
      for (let i = start; i < Math.min(start + 12, blob.length); i++) {
        if (blob[i] === 0x2b) { m = i; break; }
      }
      if (m < 0) { from = at + 1; continue; }
      let p = m + 1;
      if (p >= blob.length) return null;
      let len: number;
      const b = blob[p]!;
      if (b < 0x81) { len = b; p += 1; }
      else if (b === 0x81) {
        if (p + 3 > blob.length) return null;
        len = blob[p + 1]! | (blob[p + 2]! << 8); p += 3;
      } else if (b === 0x82) {
        if (p + 5 > blob.length) return null;
        len = (blob[p + 1]! | (blob[p + 2]! << 8) | (blob[p + 3]! << 16) | (blob[p + 4]! << 24)) >>> 0; p += 5;
      } else return null;
      if (len <= 0 || p + len > blob.length) return null;
      const s = new TextDecoder("utf-8", { fatal: true }).decode(blob.subarray(p, p + len));
      return s.length ? s : null;
    }
  } catch {
    return null;
  }
}

function appleToUnixMs(v: number): number {
  // legacy rows hold seconds; modern rows hold nanoseconds
  return v < 1e12 ? (v + APPLE_EPOCH_S) * 1000 : Math.floor(v / 1e6) + APPLE_EPOCH_S * 1000;
}
function unixMsToAppleNs(ms: number): number {
  return (ms - APPLE_EPOCH_S * 1000) * 1e6;
}

interface Row { date: number; text: string | null; attributedBody: Uint8Array | null; sender: string | null }

export function messagesSource(opts: { dbPath?: string } = {}): CodeSource {
  const dbPath = opts.dbPath ?? `${homedir()}/Library/Messages/chat.db`;
  return {
    kind: "sms",
    async fetchSince(sinceMs: number): Promise<CodeMessage[]> {
      let db: Database | undefined;
      try {
        db = new Database(dbPath, { readonly: true });
        const rows = db
          .query(
            `SELECT message.date AS date, message.text AS text, message.attributedBody AS attributedBody, handle.id AS sender
             FROM message LEFT JOIN handle ON message.handle_id = handle.ROWID
             WHERE message.is_from_me = 0 AND message.date >= ?
             ORDER BY message.date DESC LIMIT 50`,
          )
          .all(unixMsToAppleNs(sinceMs)) as Row[];
        // legacy second-valued rows are tiny numbers and would fail the ns filter; also pick them up
        const legacy = db
          .query(
            `SELECT message.date AS date, message.text AS text, message.attributedBody AS attributedBody, handle.id AS sender
             FROM message LEFT JOIN handle ON message.handle_id = handle.ROWID
             WHERE message.is_from_me = 0 AND message.date < 1000000000000 AND message.date >= ?
             ORDER BY message.date DESC LIMIT 50`,
          )
          .all(sinceMs / 1000 - APPLE_EPOCH_S) as Row[];
        const out: CodeMessage[] = [];
        const seen = new Set<Row>();
        for (const r of [...rows, ...legacy]) {
          if (seen.has(r)) continue;
          seen.add(r);
          const at = appleToUnixMs(Number(r.date));
          if (at < sinceMs) continue;
          let body = r.text && r.text.length ? r.text : null;
          if (body === null && r.attributedBody) body = decodeAttributedBody(r.attributedBody);
          if (body === null) continue;
          out.push({ at, sender: r.sender ?? "", body });
        }
        // a row can match both queries (it can't: ns rows are >= 1e12), but de-dupe defensively by order
        out.sort((a, b) => b.at - a.at);
        return out.slice(0, 50);
      } catch (e) {
        const msg = e instanceof Error ? e.message : "";
        const code = (e as { code?: string })?.code ?? "";
        if (/SQLITE_CANTOPEN|SQLITE_AUTH|SQLITE_PERM|authorization denied|unable to open|not authorized|permission/i.test(msg + " " + code)) {
          throw new CdpError("messages_access_denied", "cannot open the Messages database (grant Full Disk Access)");
        }
        throw new CdpError("source_error", "reading the Messages database failed");
      } finally {
        try { db?.close(); } catch { /* ignore */ }
      }
    },
  };
}
