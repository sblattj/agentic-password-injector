import { afterAll, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decodeAttributedBody, messagesSource } from "../src/codes/messages.ts";
import { CdpError } from "../src/cdp.ts";

// REAL NSArchiver typedstream bytes, generated on macOS with
// NSArchiver.archivedData(withRootObject: NSAttributedString(string: s)).
const HEAD = "040b73747265616d747970656481e803840140848484124e5341747472696275746564537472696e67008484084e534f626a656374008592848484084e53537472696e67019484012b";
const SHORT =
  HEAD + "13596f757220636f64652069732031323334353686840269490113928484840c4e5344696374696f6e6172790094840169008686";
const LONG =
  HEAD +
  "81a200" +
  "6162636465666768696a".repeat(15) +
  "20636f64652034383239313386840269490181a200928484840c4e5344696374696f6e6172790094840169008686";
const UNI =
  HEAD +
  "1d566f74726520636f64653a2036353433323120636166c3a920f09f94908684026949011a928484840c4e5344696374696f6e6172790094840169008686";

const fromHex = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));

describe("decodeAttributedBody", () => {
  test("short ascii (1-byte length)", () => expect(decodeAttributedBody(fromHex(SHORT))).toBe("Your code is 123456"));
  test("long string (0x81 uint16 length)", () => {
    const s = decodeAttributedBody(fromHex(LONG))!;
    expect(s.length).toBe(162);
    expect(s.endsWith("code 482913")).toBe(true);
  });
  test("non-ascii", () => expect(decodeAttributedBody(fromHex(UNI))).toBe("Votre code: 654321 café \u{1F510}"));
  test("total on garbage", () => {
    expect(decodeAttributedBody(new Uint8Array())).toBeNull();
    expect(decodeAttributedBody(Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]))).toBeNull();
    const t = fromHex(SHORT).subarray(0, 90); // truncated mid-string
    expect(decodeAttributedBody(t)).toBeNull();
    expect(decodeAttributedBody(fromHex(SHORT).subarray(0, 40))).toBeNull();
  });
});

const dir = mkdtempSync(join(tmpdir(), "apinj-msg-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const APPLE = 978307200;
const ns = (unixMs: number) => (unixMs - APPLE * 1000) * 1e6;

function fixtureDb(): string {
  const p = join(dir, "chat.db");
  const db = new Database(p);
  db.run("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT)");
  db.run(
    "CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT, attributedBody BLOB, date INTEGER, is_from_me INTEGER, handle_id INTEGER)",
  );
  db.run("INSERT INTO handle VALUES (1, '+15550001111'), (2, '+15550002222')");
  const ins = db.prepare("INSERT INTO message (text, attributedBody, date, is_from_me, handle_id) VALUES (?,?,?,?,?)");
  const base = 1_800_000_000_000;
  ins.run("Old code 111111", null, ns(base - 600_000), 0, 1);
  ins.run("Your code is 222222", null, ns(base + 10_000), 0, 1);
  ins.run(null, fromHex(SHORT), ns(base + 20_000), 0, 1);
  ins.run("my own reply 333333", null, ns(base + 30_000), 1, 1);
  ins.run("Other sender 444444", null, ns(base + 15_000), 0, 2);
  ins.run("Legacy seconds 555555", null, base / 1000 + 40 - APPLE, 0, 2);
  db.close();
  return p;
}

describe("messagesSource", () => {
  const p = fixtureDb();
  const base = 1_800_000_000_000;

  test("kind is sms", () => expect(messagesSource({ dbPath: p }).kind).toBe("sms"));

  test("orders newest first, filters since, skips is_from_me, decodes attributedBody", async () => {
    const got = await messagesSource({ dbPath: p }).fetchSince(base);
    expect(got.map((m) => m.body)).toEqual([
      "Legacy seconds 555555",
      "Your code is 123456",
      "Other sender 444444",
      "Your code is 222222",
    ]);
    expect(got.map((m) => m.at)).toEqual([base + 40_000, base + 20_000, base + 15_000, base + 10_000]);
    expect(got.map((m) => m.sender)).toEqual(["+15550002222", "+15550001111", "+15550002222", "+15550001111"]);
  });

  test("since excludes the old row and later rows", async () => {
    const got = await messagesSource({ dbPath: p }).fetchSince(base + 16_000);
    expect(got.map((m) => m.at)).toEqual([base + 40_000, base + 20_000]);
  });

  test("old row appears with an early since", async () => {
    const got = await messagesSource({ dbPath: p }).fetchSince(base - 700_000);
    expect(got.some((m) => m.body === "Old code 111111")).toBe(true);
  });

  test("missing path throws messages_access_denied", async () => {
    const err = await messagesSource({ dbPath: join(dir, "nope", "chat.db") }).fetchSince(0).catch((e) => e);
    expect(err).toBeInstanceOf(CdpError);
    expect(err.code).toBe("messages_access_denied");
  });

  test("a directory / non-database file maps to a fixed code, never leaking the path", async () => {
    const err = await messagesSource({ dbPath: dir }).fetchSince(0).catch((e) => e);
    expect(err).toBeInstanceOf(CdpError);
    expect(["messages_access_denied", "source_error"]).toContain(err.code);
    expect(String(err.message)).not.toContain(dir);
  });
});
