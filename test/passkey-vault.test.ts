import { expect, test } from "bun:test";
import { isValidRecord, passkeyLookup, passkeyStore, serializeRecord, type PasskeyRecord } from "../src/vault/passkey.ts";

const PK = "UFJJVkFURS1LRVktU0VOVElORUw=";
const REC: PasskeyRecord = { credentialId: "Q1JFRA==", rpId: "example.com", privateKey: PK, userHandle: "dWg=", signCount: 3 };
const attrs = (origin: string, acct = "example.com") =>
  `keychain: "x"\nattributes:\n    "acct"<blob>="${acct}"\n    "icmt"<blob>="${origin}"\n    "svce"<blob>="apinj-passkey:ex"\n`;

test("store writes over stdin only: the key never reaches argv", () => {
  const argv: string[][] = []; const stdin: string[] = [];
  passkeyStore("ex", "https://login.example.com", REC, {}, { run: (a) => { argv.push(a); return ""; }, runStdin: (i) => { stdin.push(i); return ""; } });
  expect(argv.flat().join(" ")).not.toContain(PK);
  expect(stdin).toHaveLength(1);
  expect(stdin[0]).toContain('-s "apinj-passkey:ex"');
  expect(stdin[0]).toContain('-a "example.com"');
  expect(stdin[0]).toContain('-j "https://login.example.com"');
  expect(stdin[0]).not.toContain(" -U ");
  expect(stdin[0].endsWith("\n")).toBe(true);
  expect(stdin[0].split("\n").length).toBe(2);
});

test("store updates in place with -U for the same rpId, and deletes the old item across rpIds", () => {
  const argv: string[][] = []; const stdin: string[] = [];
  const io = { run: (a: string[]) => { argv.push(a); return ""; }, runStdin: (i: string) => { stdin.push(i); return ""; } };
  passkeyStore("ex", "https://example.com", REC, { replace: { rpId: "example.com" } }, io);
  expect(stdin[0]).toContain("add-generic-password -U ");
  expect(argv).toHaveLength(0);
  passkeyStore("ex", "https://example.com", REC, { replace: { rpId: "old.example.com" } }, io);
  expect(stdin[1]).not.toContain(" -U ");
  expect(argv[0]).toEqual(["delete-generic-password", "-s", "apinj-passkey:ex", "-a", "old.example.com"]);
});

test("store refuses a malformed record and a write fault is vault_error without the key", () => {
  const io = { run: () => "", runStdin: () => "" };
  expect(() => passkeyStore("ex", "https://example.com", { ...REC, privateKey: 'a"b\n' }, {}, io)).toThrow("vault_error");
  expect(() => passkeyStore("ex", "https://example.com", { ...REC, signCount: -1 }, {}, io)).toThrow("vault_error");
  let msg = "";
  try { passkeyStore("ex", "https://example.com", REC, {}, { run: () => "", runStdin: () => { throw new Error(PK); } }); }
  catch (e) { msg = String((e as Error).message); }
  expect(msg).toContain("vault_error");
  expect(msg).not.toContain(PK);
});

test("lookup reads attributes only; the key is read lazily and validated", () => {
  const calls: string[][] = [];
  const e = passkeyLookup("ex", { run: (a) => { calls.push(a); return a.includes("-w") ? serializeRecord(REC) + "\n" : attrs("https://login.example.com"); } })!;
  expect(e.origin).toBe("https://login.example.com");
  expect(e.rpId).toBe("example.com");
  expect(calls).toHaveLength(1);
  expect(calls[0]).not.toContain("-w");
  expect(calls[0]).not.toContain("-g");
  expect(e.getRecord()).toEqual(REC);
  expect(calls).toHaveLength(2);
});

test("lookup: miss is null, fault is vault_locked, garbage record is vault_error", () => {
  const notFound = () => { const err: any = new Error("x"); err.status = 44; throw err; };
  expect(passkeyLookup("ex", { run: notFound })).toBeNull();
  expect(() => passkeyLookup("ex", { run: () => { const err: any = new Error(PK); err.status = 51; throw err; } })).toThrow("vault_locked");
  const e = passkeyLookup("ex", { run: (a) => a.includes("-w") ? "{not json" : attrs("https://example.com") })!;
  expect(() => e.getRecord()).toThrow("vault_error");
});

test("isValidRecord rejects extra-shaped values", () => {
  expect(isValidRecord(REC)).toBe(true);
  expect(isValidRecord({ ...REC, rpId: "Example Com" })).toBe(false);
  expect(isValidRecord({ ...REC, credentialId: "" })).toBe(false);
  expect(isValidRecord(null)).toBe(false);
});
