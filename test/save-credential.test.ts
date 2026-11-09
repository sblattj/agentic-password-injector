// test/save-credential.test.ts
//
// `save_credential` is the only tool that WRITES, and the only one where a
// secret flows INTO the server from a human rather than out of a vault. These
// tests pin the three things that matter: bad input never raises a dialog, the
// password reaches `security -i` on stdin with quoting that cannot split the
// command, and the password never comes back out of a tool boundary.
import { expect, test } from "bun:test";
import { MANIFEST, TOOLS, saveCredential, normalizeSaveOrigin, type SaveDeps } from "../src/tools.ts";
import {
  SAVE_PASSWORD_MAX, isStorablePassword, isStorableUsername, keychainExisting, keychainLookup, keychainStore,
  securityQuote, type NewCredential,
} from "../src/vault/keychain.ts";
import { buildSavePasswordDialogScript, promptForPassword } from "../src/consent.ts";
import { resolveCredentialWith } from "../src/vault/index.ts";
import { CdpError } from "../src/cdp.ts";

const PW = "S3NT1NEL-save-p\\a\"ss";
const ARGS = { name: "example", origin: "https://login.example.com/path?q=1", username: "alice@example.com" };
const ORIGIN = "https://login.example.com";

const notFound = () => Object.assign(new Error("could not be found"), { status: 44 });
const denied = () => Object.assign(new Error(`denied ${PW}`), { status: 51, stderr: `User interaction is not allowed. ${PW}` });

// ── A fake `security` that parses -i input the way the real one does ─────────
// Double-quoted tokens, `\"` and `\\` escapes, one command per line. Items are
// keyed by service+account, like the real keychain, so the `-U` trap shows up.

function tokenize(line: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < line.length) {
    if (line[i] === " ") { i++; continue; }
    if (line[i] === '"') {
      let v = ""; i++;
      while (i < line.length && line[i] !== '"') {
        if (line[i] === "\\" && i + 1 < line.length) { v += line[i + 1]; i += 2; } else { v += line[i++]; }
      }
      i++; out.push(v);
    } else {
      let v = "";
      while (i < line.length && line[i] !== " ") v += line[i++];
      out.push(v);
    }
  }
  return out;
}

interface Item { svc: string; acct: string; icmt: string; pw: string }

function fakeKeychain(seed: Item[] = []) {
  const items: Item[] = [...seed];
  const stdin: string[] = [];
  const argv: string[][] = [];
  const opt = (a: string[], f: string) => { const i = a.indexOf(f); return i >= 0 ? a[i + 1] : undefined; };
  const find = (svc: string, acct?: string) => items.find((x) => x.svc === svc && (acct === undefined || x.acct === acct));
  const runStdin = (input: string) => {
    stdin.push(input);
    for (const line of input.split("\n").filter(Boolean)) {
      const t = tokenize(line);
      if (t[0] !== "add-generic-password") throw new Error("unexpected command");
      const it: Item = { svc: opt(t, "-s")!, acct: opt(t, "-a")!, icmt: opt(t, "-j") ?? "", pw: opt(t, "-w")! };
      const hit = find(it.svc, it.acct);
      if (hit && !t.includes("-U")) throw Object.assign(new Error("exists"), { status: 45 });
      if (hit) Object.assign(hit, it); else items.push(it);
    }
    return "";
  };
  const run = (a: string[]) => {
    argv.push(a);
    const svc = opt(a, "-s")!;
    if (a[0] === "delete-generic-password") {
      const acct = opt(a, "-a");
      const i = items.findIndex((x) => x.svc === svc && (acct === undefined || x.acct === acct));
      if (i < 0) throw notFound();
      items.splice(i, 1);
      return "";
    }
    const hit = find(svc);
    if (!hit) throw notFound();
    if (a.includes("-w")) return hit.pw + "\n";
    return `"acct"<blob>="${hit.acct}"\n"icmt"<blob>="${hit.icmt}"\n"svce"<blob>="${hit.svc}"`;
  };
  return { items, stdin, argv, run, runStdin };
}

function deps(k = fakeKeychain(), prompt: SaveDeps["promptForPassword"] = async () => PW) {
  const prompts: string[][] = [];
  const d: SaveDeps = {
    keychainExisting: (n) => keychainExisting(n, k),
    keychainStore: (c, o) => keychainStore(c, o, k),
    promptForPassword: async (o, u, n) => { prompts.push([o, u, n]); return prompt(o, u, n); },
  };
  return { d, k, prompts };
}

function assertNoLeak(x: unknown) {
  const s = JSON.stringify(x) + String((x as Error)?.message ?? "") + String((x as Error)?.stack ?? "");
  expect(s).not.toContain(PW);
  expect(s).not.toContain("S3NT1NEL");
  expect(s).not.toMatch(/length|\*\*\*/i);
}

// ── 1. Validation: refused before any dialog or keychain call ────────────────

test("bad name, origin or username is refused with NO dialog and NO keychain call", async () => {
  const cases: [Record<string, unknown>, string][] = [
    [{ ...ARGS, name: "" }, "invalid_name"],
    [{ ...ARGS, name: "has space" }, "invalid_name"],
    [{ ...ARGS, name: "a".repeat(65) }, "invalid_name"],
    [{ ...ARGS, name: "-lead" }, "invalid_name"],
    [{ ...ARGS, name: 'x"y' }, "invalid_name"],
    [{ ...ARGS, origin: "" }, "invalid_origin"],
    [{ ...ARGS, origin: "example.com" }, "invalid_origin"],
    [{ ...ARGS, origin: "http://example.com" }, "invalid_origin"],
    [{ ...ARGS, origin: "ftp://example.com" }, "invalid_origin"],
    [{ ...ARGS, origin: "javascript:alert(1)" }, "invalid_origin"],
    [{ ...ARGS, origin: 42 }, "invalid_origin"],
    [{ ...ARGS, username: "" }, "invalid_username"],
    [{ ...ARGS, username: "a".repeat(129) }, "invalid_username"],
    [{ ...ARGS, username: 'a"b@example.com' }, "invalid_username"],
    [{ ...ARGS, username: "a\\b" }, "invalid_username"],
    [{ ...ARGS, username: "alice\nAllow" }, "invalid_username"],
    [{ ...ARGS, username: "jürgen@example.com" }, "invalid_username"],
    [{ ...ARGS, username: undefined }, "invalid_username"],
  ];
  for (const [a, reason] of cases) {
    const { d, k, prompts } = deps();
    expect(await saveCredential(a, d)).toEqual({ saved: false, reason });
    expect(prompts).toHaveLength(0);
    expect(k.argv).toHaveLength(0);
    expect(k.stdin).toHaveLength(0);
  }
});

test("origin is normalised to scheme://host[:port]; http only for loopback", () => {
  expect(normalizeSaveOrigin("https://Login.Example.com/a/b?c#d")).toBe("https://login.example.com");
  expect(normalizeSaveOrigin("https://example.com:8443/x")).toBe("https://example.com:8443");
  expect(normalizeSaveOrigin("http://localhost:3000/login")).toBe("http://localhost:3000");
  expect(normalizeSaveOrigin("http://127.0.0.1:8080")).toBe("http://127.0.0.1:8080");
  expect(normalizeSaveOrigin("https://user:pw@example.com/")).toBe("https://example.com");
  expect(normalizeSaveOrigin("http://localhost.example.com")).toBe(null);
  expect(normalizeSaveOrigin("http://10.0.0.1")).toBe(null);
  expect(normalizeSaveOrigin("not a url")).toBe(null);
});

// ── 2. exists / replace ──────────────────────────────────────────────────────

const OLD: Item = { svc: "apinj:example", acct: "alice@example.com", icmt: "https://old.example.com", pw: "old-pw" };

test("an existing entry is refused with `exists` and no dialog, unless replace:true", async () => {
  const { d, k, prompts } = deps(fakeKeychain([OLD]));
  expect(await saveCredential(ARGS, d)).toEqual({ saved: false, reason: "exists" });
  expect(prompts).toHaveLength(0);
  expect(k.stdin).toHaveLength(0);
  expect(k.items[0].pw).toBe("old-pw");
});

test("the existence check is attributes-only: never -g, never -w", async () => {
  const { d, k } = deps(fakeKeychain([OLD]));
  await saveCredential(ARGS, d);
  await saveCredential({ ...ARGS, replace: true }, d);
  for (const a of k.argv.filter((x) => x[0] === "find-generic-password")) {
    expect(a).not.toContain("-g");
    expect(a).not.toContain("-w");
  }
});

test("replace:true with the SAME username updates in place with -U", async () => {
  const { d, k } = deps(fakeKeychain([OLD]));
  expect(await saveCredential({ ...ARGS, replace: true }, d)).toMatchObject({ saved: true });
  expect(k.stdin[0].startsWith("add-generic-password -U ")).toBe(true);
  expect(k.items).toHaveLength(1);
  expect(k.items[0]).toEqual({ svc: "apinj:example", acct: "alice@example.com", icmt: ORIGIN, pw: PW });
});

test("replace:true with a DIFFERENT username leaves exactly one item: add new, then delete old", async () => {
  const { d, k } = deps(fakeKeychain([OLD]));
  const r = await saveCredential({ ...ARGS, username: "bob@example.com", replace: true }, d);
  expect(r).toMatchObject({ saved: true, username: "bob@example.com" });
  expect(k.stdin[0]).not.toContain("-U");
  const del = k.argv.find((a) => a[0] === "delete-generic-password")!;
  expect(del).toEqual(["delete-generic-password", "-s", "apinj:example", "-a", "alice@example.com"]);
  expect(k.items).toEqual([{ svc: "apinj:example", acct: "bob@example.com", icmt: ORIGIN, pw: PW }]);
});

test("a FAILED add during a replace never deletes the old credential", async () => {
  const k = fakeKeychain([OLD]);
  const { d } = deps({ ...k, runStdin: () => { throw denied(); } } as ReturnType<typeof fakeKeychain>);
  const r = await saveCredential({ ...ARGS, username: "bob@example.com", replace: true }, d);
  expect(r).toEqual({ saved: false, reason: "vault_error" });
  expect(k.items).toEqual([OLD]);
  assertNoLeak(r);
});

test("a locked keychain at the existence check is a vault fault, not `exists` or a dialog", async () => {
  const k = fakeKeychain();
  const { d, prompts } = deps({ ...k, run: () => { throw denied(); } } as ReturnType<typeof fakeKeychain>);
  const r = await saveCredential(ARGS, d);
  expect(r).toEqual({ saved: false, reason: "vault_locked" });
  expect(prompts).toHaveLength(0);
  assertNoLeak(r);
});

// ── 3. The dialog ────────────────────────────────────────────────────────────

test("cancel, timeout (empty) and a throwing dialog are all user_cancelled, with no write", async () => {
  for (const p of [async () => null, async () => "", async () => { throw new Error(`boom ${PW}`); }] as SaveDeps["promptForPassword"][]) {
    const { d, k } = deps(fakeKeychain(), p);
    const r = await saveCredential(ARGS, d);
    expect(r).toEqual({ saved: false, reason: "user_cancelled" });
    expect(k.stdin).toHaveLength(0);
    assertNoLeak(r);
  }
});

test("the dialog is shown with the NORMALISED origin, the username and the entry name", async () => {
  const { d, prompts } = deps();
  await saveCredential(ARGS, d);
  expect(prompts).toEqual([[ORIGIN, "alice@example.com", "example"]]);
});

test("the dialog ignores APINJ_CONFIRM: it is shown even when confirmation is off", async () => {
  const prev = process.env.APINJ_CONFIRM;
  process.env.APINJ_CONFIRM = "0";
  try {
    const { d, prompts } = deps();
    await saveCredential(ARGS, d);
    expect(prompts).toHaveLength(1);
  } finally {
    if (prev === undefined) delete process.env.APINJ_CONFIRM; else process.env.APINJ_CONFIRM = prev;
  }
});

test("dialog script: hidden answer, text only, exact wording", () => {
  const s = buildSavePasswordDialogScript(ORIGIN, "alice@example.com", "example");
  expect(s).toBe(
    `text returned of (display dialog "Save a login for login.example.com as alice@example.com (entry 'example')? ` +
    `Paste the password:" default answer "" with hidden answer buttons {"Cancel","Save"} default button "Save" ` +
    `cancel button "Cancel" with title "agentic-password-injector" giving up after 120)`,
  );
});

test("dialog script: hostile username and name cannot break out of the AppleScript string", () => {
  const s = buildSavePasswordDialogScript(ORIGIN, 'x" & (do shell script "id") & "\\\n', 'bad" name');
  const body = s.slice(s.indexOf('display dialog "') + 16, s.indexOf('" default answer'));
  expect(body).not.toContain('"');
  expect(body).not.toContain("\n");
  expect(body).toContain("entry 'unnamed'");
});

test("promptForPassword strips ONE trailing newline, maps empty and throw to null", async () => {
  expect(await promptForPassword(ORIGIN, "a", "n", () => " pw \n")).toBe(" pw ");
  expect(await promptForPassword(ORIGIN, "a", "n", () => "\n")).toBe(null);
  expect(await promptForPassword(ORIGIN, "a", "n", () => "")).toBe(null);
  expect(await promptForPassword(ORIGIN, "a", "n", () => { throw Object.assign(new Error("-128"), { status: 1 }); })).toBe(null);
});

// ── 4. The write: stdin, quoting, refusal ────────────────────────────────────

test("success writes ONE stdin line with every value quoted, and nothing secret on argv", async () => {
  const { d, k } = deps();
  const r = await saveCredential(ARGS, d);
  expect(r).toEqual({ saved: true, name: "example", origin: ORIGIN, username: "alice@example.com", backend: "keychain" });
  expect(k.stdin).toEqual([
    `add-generic-password -s "apinj:example" -a "alice@example.com" -j "${ORIGIN}" -w "S3NT1NEL-save-p\\\\a\\"ss"\n`,
  ]);
  expect(k.items).toEqual([{ svc: "apinj:example", acct: "alice@example.com", icmt: ORIGIN, pw: PW }]);
  for (const a of k.argv) expect(a.join(" ")).not.toContain("S3NT1NEL");
});

test("securityQuote escapes \" and \\ and round-trips through the -i tokenizer", () => {
  for (const v of ['a"b', "a\\b", "ab\\", 'a\\"b', "\\\\", '""', "it's", "$HOME `x` {}[]|&;#!*?~%^", "-w x"]) {
    const q = securityQuote(v);
    expect(tokenize(`cmd ${q}`)).toEqual(["cmd", v]);
  }
  expect(securityQuote('a"b\\c')).toBe('"a\\"b\\\\c"');
});

test("securityQuote refuses a newline, CR, tab, NUL or non-ASCII byte itself, with fixed text", () => {
  for (const v of [`x\n-w evil`, "x\ry", "a\tb", "a\x00b", "pässwörd"]) {
    let err: any;
    try { securityQuote(v); } catch (e) { err = e; }
    expect(err).toBeInstanceOf(CdpError);
    expect(err.message).toBe("vault_error: value cannot be written safely");
  }
});

test("a password the read path would mangle is refused AFTER the dialog, with no security call", async () => {
  for (const pw of [
    "line1\nadd-generic-password -s \"apinj:evil\" -a x -w y", "a\rb", "a\tb", "pässwörd€",
    " lead", "trail ", "x".repeat(SAVE_PASSWORD_MAX + 1),
  ]) {
    const { d, k, prompts } = deps(fakeKeychain(), async () => pw);
    const r = await saveCredential(ARGS, d);
    expect(r).toEqual({ saved: false, reason: "password_unsupported" });
    expect(prompts).toHaveLength(1);
    expect(k.stdin).toHaveLength(0);
    expect(JSON.stringify(r)).not.toContain(pw);
  }
});

test("the length cap: exactly SAVE_PASSWORD_MAX of the worst-case char is accepted", async () => {
  const pw = '"'.repeat(SAVE_PASSWORD_MAX);
  const { d, k } = deps(fakeKeychain(), async () => pw);
  expect(await saveCredential(ARGS, d)).toMatchObject({ saved: true });
  // Far below the ~4 KB line buffer where `security -i` truncated a value.
  expect(k.stdin[0].length).toBeLessThan(2400);
  expect(k.items[0].pw).toBe(pw);
});

test("isStorablePassword / isStorableUsername", () => {
  expect(isStorablePassword("p a\"ss\\")).toBe(true);
  expect(isStorablePassword("")).toBe(false);
  expect(isStorablePassword("a b")).toBe(false);
  expect(isStorableUsername("alice smith")).toBe(true);
  expect(isStorableUsername("a".repeat(128))).toBe(true);
  expect(isStorableUsername("a\x7fb")).toBe(false);
});

test("keychainStore re-checks its input even when called directly", () => {
  const k = fakeKeychain();
  const c: NewCredential = { name: "example", origin: ORIGIN, username: "alice", password: "a\nb" };
  expect(() => keychainStore(c, {}, k)).toThrow("value cannot be written safely");
  expect(k.stdin).toHaveLength(0);
});

test("a write fault is a fixed vault_error with no security output in it", async () => {
  const k = fakeKeychain();
  const { d } = deps({ ...k, runStdin: () => { throw denied(); } } as ReturnType<typeof fakeKeychain>);
  const r = await saveCredential(ARGS, d);
  expect(r).toEqual({ saved: false, reason: "vault_error" });
  assertNoLeak(r);
});

test("keychainStore errors carry fixed text, never the password or stderr", () => {
  const k = fakeKeychain();
  let err: any;
  try {
    keychainStore({ name: "example", origin: ORIGIN, username: "alice", password: PW }, {}, { ...k, runStdin: () => { throw denied(); } });
  } catch (e) { err = e; }
  expect(err).toBeInstanceOf(CdpError);
  expect(err.code).toBe("vault_error");
  assertNoLeak(err);
});

// ── 5. Leak sweep: every return branch ───────────────────────────────────────

test("LEAK: no branch of saveCredential returns the password, its length, or a mask", async () => {
  const runs: [Record<string, unknown>, ReturnType<typeof deps>][] = [
    [ARGS, deps()],
    [ARGS, deps(fakeKeychain([OLD]))],
    [{ ...ARGS, replace: true }, deps(fakeKeychain([OLD]))],
    [{ ...ARGS, username: "bob@example.com", replace: true }, deps(fakeKeychain([OLD]))],
    [ARGS, deps(fakeKeychain(), async () => null)],
    [ARGS, deps(fakeKeychain(), async () => PW + "\t")],
    [{ ...ARGS, name: "bad name" }, deps()],
  ];
  for (const [a, { d }] of runs) {
    const r = await saveCredential(a, d);
    assertNoLeak(r);
    expect(Object.keys(r).sort()).toEqual(
      r.saved ? ["backend", "name", "origin", "saved", "username"] : ["reason", "saved"],
    );
  }
});

test("LEAK mutation check: assertNoLeak actually fails on a leaked value", () => {
  expect(() => assertNoLeak({ saved: true, echo: PW })).toThrow();
  expect(() => assertNoLeak({ saved: true, length: 12 })).toThrow();
});

// ── 6. A saved entry is what login({domain, name}) resolves ──────────────────

test("after a save, resolveCredentialWith({name}) finds it via the keychain backend, intact", async () => {
  const { d, k } = deps();
  await saveCredential(ARGS, d);
  const r = await resolveCredentialWith(
    {
      vivaldi: async () => null,
      // A browser row for the same domain with a different username must not win.
      arc: async () => ({ origin: ORIGIN, username: "someone-else", getSecret: () => "x" }),
      keychain: (n) => keychainLookup(n, k),
    },
    "login.example.com",
    { name: "example" },
  );
  expect(r).toMatchObject({ backend: "keychain" });
  const cred = (r as { cred: { origin: string; username: string; getSecret: () => string } }).cred;
  expect(cred.origin).toBe(ORIGIN);
  expect(cred.username).toBe("alice@example.com");
  expect(cred.getSecret()).toBe(PW);
});

// ── 7. Registration ──────────────────────────────────────────────────────────

test("save_credential is registered; the description tells the model it never sees the password", async () => {
  const t = MANIFEST.find((m) => m.name === "save_credential")!;
  expect(t.description).toContain("native");
  expect(t.description).toContain("model never sees it");
  expect(await TOOLS.save_credential({ ...ARGS, name: "bad name" })).toEqual({ saved: false, reason: "invalid_name" });
  expect(await TOOLS.save_credential({ ...ARGS, origin: "http://example.com" })).toEqual({ saved: false, reason: "invalid_origin" });
});
