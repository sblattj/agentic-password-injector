import { expect, test } from "bun:test";
import { decideGate } from "../src/gate.ts";

const base = { tabOrigin: "https://x.com", savedOrigin: "https://x.com", allow: true };

test("passes when origin matches and user allows", () => expect(decideGate(base)).toEqual({ ok: true }));

test("blocks on origin mismatch BEFORE consent", () => {
  expect(decideGate({ ...base, tabOrigin: "https://evil.com" })).toEqual({ ok: false, reason: "origin_mismatch" });
});

test("blocks when user denies", () => expect(decideGate({ ...base, allow: false })).toEqual({ ok: false, reason: "user_denied" }));

// Invariant #1: origin-match is checked FIRST. A mismatch must short-circuit with
// origin_mismatch even when the user would have allowed — and, critically, even when
// the user denied, the *origin* is the reason reported, proving the ordering.
test("origin mismatch wins over user_denied (order proof)", () => {
  expect(decideGate({ tabOrigin: "https://evil.com", savedOrigin: "https://x.com", allow: false }))
    .toEqual({ ok: false, reason: "origin_mismatch" });
});

test("scheme mismatch is an origin mismatch", () => {
  expect(decideGate({ ...base, tabOrigin: "http://x.com" })).toEqual({ ok: false, reason: "origin_mismatch" });
});

test("port mismatch is an origin mismatch", () => {
  expect(decideGate({ tabOrigin: "https://x.com:8443", savedOrigin: "https://x.com", allow: true }))
    .toEqual({ ok: false, reason: "origin_mismatch" });
});

test("subdomain is NOT an origin match", () => {
  expect(decideGate({ ...base, tabOrigin: "https://evil.x.com" })).toEqual({ ok: false, reason: "origin_mismatch" });
});

test("an empty/unreadable tab origin blocks", () => {
  expect(decideGate({ ...base, tabOrigin: "" })).toEqual({ ok: false, reason: "origin_mismatch" });
});

test("default https port is equivalent to no port", () => {
  expect(decideGate({ tabOrigin: "https://x.com:443", savedOrigin: "https://x.com", allow: true })).toEqual({ ok: true });
});
