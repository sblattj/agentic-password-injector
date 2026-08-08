// test/origin.test.ts
//
// `originMatches` is THE anti-phishing boundary: it is the only thing standing
// between "the human approved mybank.com" and "the password was typed into the
// page currently in the tab". Everything below is a regression lock on a crafted
// origin that must not read as a match.
import { expect, test } from "bun:test";
import { originMatches } from "../src/origin.ts";
test("exact match", () => expect(originMatches("https://auth.examplebank.com", "https://auth.examplebank.com")).toBe(true));
test("port normalization", () => expect(originMatches("https://x.com:443", "https://x.com")).toBe(true));
test("subdomain is NOT a match", () => expect(originMatches("https://examplebank.com", "https://auth.examplebank.com")).toBe(false));
test("scheme mismatch blocks", () => expect(originMatches("http://x.com", "https://x.com")).toBe(false));
test("empty tab origin blocks", () => expect(originMatches("", "https://x.com")).toBe(false));

// ── userinfo must never spoof the host ───────────────────────────────────────
// `https://x.com@evil.com` is a URL whose HOST is evil.com; `x.com` is a
// username. Any comparison that reads the string left-to-right (a `startsWith`,
// a `split("/")[2]`, a naive "contains the saved domain") calls this a match and
// hands the bank password to evil.com. It is also exactly what a phishing link
// looks like in an address bar the user glanced at.
test("userinfo does not spoof the host: x.com@evil.com is evil.com", () => {
  expect(originMatches("https://x.com@evil.com", "https://x.com")).toBe(false);
  expect(originMatches("https://x.com@evil.com", "https://evil.com")).toBe(true);
  // The saved side is parsed by the same rule, so a poisoned binding cannot
  // widen a match either.
  expect(originMatches("https://evil.com", "https://x.com@evil.com")).toBe(true);
  expect(originMatches("https://x.com", "https://x.com@evil.com")).toBe(false);
});

test("password-style userinfo is stripped, not compared", () => {
  expect(originMatches("https://user:pw@x.com", "https://x.com")).toBe(true);
  expect(originMatches("https://user:pw@x.com", "https://user:other@x.com")).toBe(true);
});

// ── a non-default port is a DIFFERENT origin ─────────────────────────────────
// Same host, different port = a different server (a dev proxy, a compromised
// service on a high port, a local attacker on 8443). Only the scheme's default
// port is normalized away.
test("a non-default port does not match the bare origin", () => {
  expect(originMatches("https://x.com:8443", "https://x.com")).toBe(false);
  expect(originMatches("https://x.com:8443", "https://x.com:443")).toBe(false);
  expect(originMatches("https://x.com:8443", "https://x.com:8443")).toBe(true);
  // ...while the default port on each scheme still normalizes.
  expect(originMatches("http://x.com:80", "http://x.com")).toBe(true);
  expect(originMatches("http://x.com:80", "https://x.com:443")).toBe(false);
});

// ── crafted forms from the security review ───────────────────────────────────
test("case folding is host-only and does not widen the match", () => {
  expect(originMatches("https://X.COM", "https://x.com")).toBe(true);
  expect(originMatches("HTTPS://x.com", "https://x.com")).toBe(true);
  expect(originMatches("https://X.COM", "https://x.co")).toBe(false);
});

test("a trailing-dot (root-absolute) host fails closed", () => {
  // `x.com.` and `x.com` resolve identically in DNS, so a mismatch here is a
  // refusal, never a false ALLOW — the direction that is safe to be wrong in.
  expect(originMatches("https://x.com.", "https://x.com")).toBe(false);
  expect(originMatches("https://x.com", "https://x.com.")).toBe(false);
});

test("path, query and fragment are not part of the origin", () => {
  expect(originMatches("https://x.com/login?next=/evil#f", "https://x.com")).toBe(true);
});

test("a non-http scheme never matches a site", () => {
  expect(originMatches("javascript:alert(1)", "https://x.com")).toBe(false);
  expect(originMatches("about:blank", "https://x.com")).toBe(false);
  expect(originMatches("data:text/html,<b>x.com</b>", "https://x.com")).toBe(false);
  expect(originMatches("file:///x.com", "https://x.com")).toBe(false);
});

test("an unparseable origin on either side blocks", () => {
  expect(originMatches("not a url", "https://x.com")).toBe(false);
  expect(originMatches("https://x.com", "")).toBe(false);
  expect(originMatches("", "")).toBe(false);
});

test("lookalike hosts are not matches", () => {
  expect(originMatches("https://evilx.com", "https://x.com")).toBe(false);
  expect(originMatches("https://x.com.evil.com", "https://x.com")).toBe(false);
  expect(originMatches("https://x-com.evil", "https://x.com")).toBe(false);
});
