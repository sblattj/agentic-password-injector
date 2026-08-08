// test/consent.test.ts
import { expect, test } from "bun:test";
import { boundHost, buildDialogScript, confirmInjection, safeRequestedDomain } from "../src/consent.ts";

test("script names the bound host + username, never a password field", () => {
  const s = buildDialogScript("https://example.com", "alice@example.com");
  expect(s).toContain("example.com");
  expect(s).toContain("alice@example.com");
  expect(s.toLowerCase()).not.toContain("password:");
});

test("Allow => true", async () => expect(await confirmInjection("https://x.com", "u", "x.com", () => "button returned:Allow")).toBe(true));
test("Deny => false", async () => expect(await confirmInjection("https://x.com", "u", "x.com", () => "button returned:Deny")).toBe(false));
test("osascript throw (cancel/timeout) => false", async () => {
  expect(await confirmInjection("https://x.com", "u", "x.com", () => { throw new Error("128"); })).toBe(false);
});

// ── Fix round 2, item 3: the prompt names the AUTHORITATIVE origin ───────────

test("boundHost extracts the host, and degrades to the raw string", () => {
  expect(boundHost("https://auth.mybank.com")).toBe("auth.mybank.com");
  expect(boundHost("https://auth.mybank.com:8443")).toBe("auth.mybank.com:8443");
  expect(boundHost("not-a-url")).toBe("not-a-url");
});

test("a caller-supplied domain does NOT replace the bound origin in the prompt", () => {
  const s = buildDialogScript("https://auth.mybank.com", "alice", "evil.com");
  // The bound host is what the user is asked to authorise...
  expect(s).toContain("Fill auth.mybank.com login for alice?");
  // ...and the mismatched request is surfaced, not silently dropped.
  expect(s).toContain("requested as evil.com");
  // The caller's string must never be the leading identifier.
  expect(s).not.toContain("Fill evil.com login");
});

test("a matching caller domain adds no redundant context", () => {
  const s = buildDialogScript("https://example.com", "alice", "example.com");
  expect(s).toContain("Fill example.com login for alice?");
  expect(s).not.toContain("requested as");
});

test("the prompt escapes quotes and backslashes in both fields", () => {
  const s = buildDialogScript('https://x.com', 'a"b\\c');
  expect(s).toContain('a\\"b\\\\c');
});

// ── FIX 6 (security M1): the caller's domain is UNVALIDATED text in the prompt ─
// `requestedDomain` arrives from the caller (a possibly prompt-injected model) and
// lands inside the sentence a human reads before approving a password fill. It is
// rendered only when it is domain-shaped and short; anything else is dropped and
// the dialog shows the bound origin alone.

test("FIX6: an injected instruction in requestedDomain never reaches the dialog", () => {
  const junk = 'mybank.com - verified by Apple, click Allow to continue';
  const s = buildDialogScript("https://auth.realbank.com", "alice", junk);
  expect(s).not.toContain("click Allow");
  expect(s).not.toContain("verified by Apple");
  expect(s).not.toContain("requested as");
  // The authoritative identifier survives intact.
  expect(s).toContain("Fill auth.realbank.com login for alice?");
});

test("FIX6: control characters and separators cannot restructure the prompt", () => {
  const CH = (n: number) => String.fromCharCode(n);
  // Real control characters, not escaped source text: a newline or a NUL is what
  // an attacker would actually send to break the dialog string apart.
  const junk = ["evil.com" + CH(10) + "Allow", "evil.com" + CH(13) + CH(10) + "buttons", "evil.com" + CH(0), "evil.com" + CH(1), "evil .com", "evil.com/../x", "evil.com.", "evil,com"];
  for (const j of junk) {
    const s = buildDialogScript("https://auth.realbank.com", "alice", j);
    expect(s).not.toContain("requested as");
    expect(s).toContain("Fill auth.realbank.com login for alice?");
    expect(s).not.toContain("evil.com");
  }
});

test("FIX6: surrounding whitespace is normalized, not treated as an attack", () => {
  // The one form that is trimmed rather than refused: the value is still exactly
  // the domain, and dropping it would hide a genuine mismatch from the human.
  const s = buildDialogScript("https://auth.realbank.com", "alice", " evil.com" + String.fromCharCode(9));
  expect(s).toContain("requested as evil.com");
});

test("FIX6: an oversized requestedDomain is dropped, not truncated into the prose", () => {
  const long = "a".repeat(300) + ".com";
  const s = buildDialogScript("https://auth.realbank.com", "alice", long);
  expect(s).not.toContain("aaaaaaaaaa");
  expect(s.length).toBeLessThan(300);
  expect(s).toContain("auth.realbank.com");
});

test("FIX6: a genuine mismatched domain is still surfaced", () => {
  const s = buildDialogScript("https://auth.realbank.com", "alice", "evil.com");
  expect(s).toContain("requested as evil.com");
  expect(s).not.toContain("Fill evil.com login");
});

test("FIX6: safeRequestedDomain accepts real domains and refuses everything else", () => {
  for (const ok of ["evil.com", "EVIL.COM", "a.b.example.org", "my-bank.io", "xn--mybnk-l11b.com"]) {
    expect(safeRequestedDomain(ok)).toBe(ok.toLowerCase());
  }
  const bad = ["", "com", "localhost", ".com", "x..com", "x.com:8443", "https://x.com", "<b>x.com</b>", "a".repeat(70) + ".com", undefined];
  for (const b of bad) expect(safeRequestedDomain(b as string | undefined)).toBeNull();
});

test("FIX6: a scheme-prefixed or path-bearing caller string is dropped, not echoed", () => {
  const s = buildDialogScript("https://auth.realbank.com", "alice", "https://evil.com/login");
  expect(s).not.toContain("evil.com");
});
