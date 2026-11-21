// Email source: Gmail REST API via a Google OAuth "authorized user" token file.
// Access tokens live in memory only; the file is never written. Errors carry
// fixed text only (no token, body, sender, or response content).
import { readFileSync } from "node:fs";
import { CdpError } from "../cdp.ts";
import type { CodeMessage, CodeSource } from "./types.ts";

interface TokenFile {
  client_id?: string;
  client_secret?: string;
  refresh_token?: string;
  token?: string;
  expiry?: string;
  token_uri?: string;
}
interface Part {
  mimeType?: string;
  headers?: { name: string; value: string }[];
  body?: { data?: string };
  parts?: Part[];
}

const API = "https://gmail.googleapis.com/gmail/v1/users/me/messages";
const unavailable = () => new CdpError("email_source_unavailable", "no Gmail token file configured");
const failed = () => new CdpError("email_source_error", "the Gmail request failed");

function parseExpiry(s: string | undefined): number {
  if (!s) return 0;
  const hasZone = /(Z|[+-]\d\d:?\d\d)$/i.test(s);
  const t = Date.parse(hasZone ? s : s + "Z");
  return Number.isFinite(t) ? t : 0;
}

function b64url(data: string): string {
  return Buffer.from(data.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
}

function findPart(p: Part, mime: string): string | null {
  if (p.mimeType === mime && p.body?.data) return b64url(p.body.data);
  for (const c of p.parts ?? []) {
    const r = findPart(c, mime);
    if (r !== null) return r;
  }
  return null;
}

function stripHtml(h: string): string {
  return h
    .replace(/<(style|script)[\s\S]*?<\/\1>/gi, " ")
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
}

export function gmailSource(
  opts: { tokenFile?: string; fetch?: typeof fetch; now?: () => number } = {},
): CodeSource {
  const doFetch = opts.fetch ?? fetch;
  const now = opts.now ?? (() => Date.now());
  let access: { token: string; expiry: number } | null = null;

  async function req(url: string, init?: RequestInit): Promise<unknown> {
    const res = await doFetch(url, { ...init, signal: AbortSignal.timeout(10_000) });
    if (!res.ok) throw failed();
    return res.json();
  }

  async function accessToken(tf: TokenFile): Promise<string> {
    if (access && access.expiry - now() > 60_000) return access.token;
    const fileExpiry = parseExpiry(tf.expiry);
    if (tf.token && fileExpiry - now() > 60_000) {
      access = { token: tf.token, expiry: fileExpiry };
      return tf.token;
    }
    if (!tf.refresh_token || !tf.client_id || !tf.client_secret) throw failed();
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: tf.refresh_token,
      client_id: tf.client_id,
      client_secret: tf.client_secret,
    });
    const j = (await req(tf.token_uri || "https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    })) as { access_token?: string; expires_in?: number };
    if (!j?.access_token) throw failed();
    access = { token: j.access_token, expiry: now() + (Number(j.expires_in) || 3600) * 1000 };
    return access.token;
  }

  return {
    kind: "email",
    async fetchSince(sinceMs: number): Promise<CodeMessage[]> {
      const file = opts.tokenFile ?? process.env.APINJ_GMAIL_TOKEN_FILE;
      if (!file) throw unavailable();
      let raw: string;
      try {
        raw = readFileSync(file, "utf8");
      } catch {
        throw unavailable();
      }
      try {
        const tf = JSON.parse(raw) as TokenFile;
        const tok = await accessToken(tf);
        const headers = { authorization: `Bearer ${tok}` };
        const after = Math.floor((sinceMs - 1000) / 1000);
        const q = encodeURIComponent(`after:${after} newer_than:1d`);
        const list = (await req(`${API}?q=${q}&maxResults=10`, { headers })) as { messages?: { id: string }[] };
        const out: CodeMessage[] = [];
        for (const m of list.messages ?? []) {
          const msg = (await req(`${API}/${encodeURIComponent(m.id)}?format=full`, { headers })) as Part & {
            internalDate?: string;
            payload?: Part;
          };
          const at = Number(msg.internalDate);
          if (!Number.isFinite(at) || at < sinceMs) continue;
          const payload = msg.payload ?? {};
          const hdr = (n: string) =>
            payload.headers?.find((h) => h.name.toLowerCase() === n)?.value ?? "";
          let text = findPart(payload, "text/plain");
          if (text === null) {
            const html = findPart(payload, "text/html");
            text = html === null ? "" : stripHtml(html);
          }
          out.push({ at, sender: hdr("from"), body: `${hdr("subject")}\n${text}` });
        }
        out.sort((a, b) => b.at - a.at);
        return out;
      } catch (e) {
        if (e instanceof CdpError) throw e;
        throw failed();
      }
    },
  };
}
