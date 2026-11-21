import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gmailSource } from "../src/codes/gmail.ts";
import { CdpError } from "../src/cdp.ts";

const dir = mkdtempSync(join(tmpdir(), "apinj-gmail-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const REFRESH = "refresh-SECRET-abc";
const OLD_ACCESS = "access-SECRET-old";
const NEW_ACCESS = "access-SECRET-new";
const NOW = Date.parse("2026-11-20T12:00:00Z");

function tokenFile(over: Record<string, unknown> = {}): string {
  const p = join(dir, `tok-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(
    p,
    JSON.stringify({
      client_id: "cid",
      client_secret: "csecret-SECRET",
      refresh_token: REFRESH,
      token: OLD_ACCESS,
      expiry: "2026-11-20T11:00:00", // no Z: UTC, expired
      token_uri: "https://oauth2.example.test/token",
      ...over,
    }),
  );
  return p;
}

const b64u = (s: string) => Buffer.from(s, "utf8").toString("base64url");

function fakeFetch(messages: Record<string, unknown>, opts: { status?: number } = {}) {
  const urls: string[] = [];
  const auth: (string | null)[] = [];
  const f = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    urls.push(url);
    auth.push(new Headers(init?.headers).get("authorization"));
    if (opts.status) return new Response("{}", { status: opts.status });
    if (url.startsWith("https://oauth2.example.test/token"))
      return Response.json({ access_token: NEW_ACCESS, expires_in: 3600 });
    if (url.includes("/messages?"))
      return Response.json({ messages: Object.keys(messages).map((id) => ({ id })) });
    const id = decodeURIComponent(url.split("/messages/")[1]!.split("?")[0]!);
    return Response.json(messages[id]);
  }) as unknown as typeof fetch;
  return { f, urls, auth };
}

const msg = (at: number, subject: string, payload: Record<string, unknown>) => ({
  internalDate: String(at),
  payload: { headers: [{ name: "Subject", value: subject }, { name: "From", value: "Acme <noreply@acme.test>" }], ...payload },
});

describe("gmailSource", () => {
  test("unset env and no tokenFile -> email_source_unavailable", async () => {
    const saved = process.env.APINJ_GMAIL_TOKEN_FILE;
    delete process.env.APINJ_GMAIL_TOKEN_FILE;
    try {
      const err = await gmailSource().fetchSince(0).catch((e) => e);
      expect(err).toBeInstanceOf(CdpError);
      expect(err.code).toBe("email_source_unavailable");
    } finally {
      if (saved !== undefined) process.env.APINJ_GMAIL_TOKEN_FILE = saved;
    }
  });

  test("missing file -> email_source_unavailable", async () => {
    const err = await gmailSource({ tokenFile: join(dir, "absent.json") }).fetchSince(0).catch((e) => e);
    expect(err.code).toBe("email_source_unavailable");
  });

  test("refreshes when expired, file unchanged, newer first, multipart parsed", async () => {
    const file = tokenFile();
    const before = readFileSync(file, "utf8");
    const since = NOW - 60_000;
    const { f, urls, auth } = fakeFetch({
      a: msg(NOW - 30_000, "Older", { mimeType: "text/plain", body: { data: b64u("Your code is 111222") } }),
      b: msg(NOW - 10_000, "Newer", {
        mimeType: "multipart/alternative",
        parts: [
          { mimeType: "text/html", body: { data: b64u("<p>html 999999</p>") } },
          {
            mimeType: "multipart/mixed",
            parts: [{ mimeType: "text/plain", body: { data: b64u("Use 333444 to sign in") } }],
          },
        ],
      }),
      c: msg(NOW - 120_000, "Too old", { mimeType: "text/plain", body: { data: b64u("x 555666") } }),
      d: msg(NOW - 5_000, "Html only", {
        mimeType: "multipart/alternative",
        parts: [{ mimeType: "text/html", body: { data: b64u("<div>Code: <b>777888</b><style>p{}</style></div>") } }],
      }),
    });
    const got = await gmailSource({ tokenFile: file, fetch: f, now: () => NOW }).fetchSince(since);
    expect(got.map((m) => m.body)).toEqual([
      "Html only\nCode: 777888",
      "Newer\nUse 333444 to sign in",
      "Older\nYour code is 111222",
    ]);
    expect(got[0]!.sender).toBe("Acme <noreply@acme.test>");
    expect(got.map((m) => m.at)).toEqual([NOW - 5_000, NOW - 10_000, NOW - 30_000]);
    expect(urls[0]).toStartWith("https://oauth2.example.test/token");
    const list = urls.find((u) => u.includes("/messages?"))!;
    const q = decodeURIComponent(new URL(list).searchParams.get("q")!);
    expect(q).toBe(`after:${Math.floor((since - 1000) / 1000)} newer_than:1d`);
    expect(new URL(list).searchParams.get("maxResults")).toBe("10");
    expect(urls.some((u) => u.includes("format=full"))).toBe(true);
    expect(auth.filter((a) => a).every((a) => a === `Bearer ${NEW_ACCESS}`)).toBe(true);
    expect(readFileSync(file, "utf8")).toBe(before);
  });

  test("valid token is used without a refresh", async () => {
    const file = tokenFile({ expiry: "2026-11-20T13:00:00Z" });
    const { f, urls, auth } = fakeFetch({});
    await gmailSource({ tokenFile: file, fetch: f, now: () => NOW }).fetchSince(0);
    expect(urls.some((u) => u.includes("oauth2"))).toBe(false);
    expect(auth[0]).toBe(`Bearer ${OLD_ACCESS}`);
  });

  test("HTTP 401 -> email_source_error with no token in the message", async () => {
    const file = tokenFile({ expiry: "2026-11-20T13:00:00Z" });
    const { f } = fakeFetch({}, { status: 401 });
    const err = await gmailSource({ tokenFile: file, fetch: f, now: () => NOW }).fetchSince(0).catch((e) => e);
    expect(err).toBeInstanceOf(CdpError);
    expect(err.code).toBe("email_source_error");
    for (const s of [REFRESH, OLD_ACCESS, NEW_ACCESS, "csecret-SECRET"]) expect(String(err.message)).not.toContain(s);
  });

  test("failed refresh and network throw -> email_source_error, no secrets", async () => {
    const file = tokenFile();
    const boom = (async () => {
      throw new Error(`network down ${REFRESH}`);
    }) as unknown as typeof fetch;
    const err = await gmailSource({ tokenFile: file, fetch: boom, now: () => NOW }).fetchSince(0).catch((e) => e);
    expect(err.code).toBe("email_source_error");
    expect(String(err.message)).not.toContain(REFRESH);
  });

  test("corrupt token file -> email_source_error", async () => {
    const p = join(dir, "bad.json");
    writeFileSync(p, "{not json");
    const err = await gmailSource({ tokenFile: p }).fetchSince(0).catch((e) => e);
    expect(err.code).toBe("email_source_error");
  });
});
