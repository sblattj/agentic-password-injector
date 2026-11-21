// test/consent-timeout.test.ts
//
// Issue #1, unit level: the timeout knob, the outcome vocabulary, the async
// runner, and the gate's handling of a cancelled request. The end-to-end proof
// through the real server is test/consent-gateway.test.ts.
import { expect, test } from "bun:test";
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CONSENT_TIMEOUT_DEFAULT_S, buildDialogScript, buildKindDialogScript, buildSecretDialogScript,
  confirmInjection, consentTimeoutS, osascriptRunner, parseConsent,
} from "../src/consent.ts";
import { gatedOnOrigin, type GateDeps } from "../src/gated.ts";
import { runWithRequestSignal } from "../src/request.ts";
import type { Send } from "../src/cdp.ts";

test("default timeout is below a 30 s gateway", () => {
  expect(CONSENT_TIMEOUT_DEFAULT_S).toBeLessThan(30);
  expect(consentTimeoutS({})).toBe(25);
});

test("APINJ_CONSENT_TIMEOUT_S: whole numbers 1..600 only, else the default", () => {
  expect(consentTimeoutS({ APINJ_CONSENT_TIMEOUT_S: "12" })).toBe(12);
  expect(consentTimeoutS({ APINJ_CONSENT_TIMEOUT_S: " 90 " })).toBe(90);
  expect(consentTimeoutS({ APINJ_CONSENT_TIMEOUT_S: "600" })).toBe(600);
  for (const v of ["", "0", "601", "-5", "2.5", "abc", "10; do shell script \"x\"", "1e3"]) {
    expect(consentTimeoutS({ APINJ_CONSENT_TIMEOUT_S: v })).toBe(25);
  }
});

test("every Allow/Deny dialog uses the configured timeout, never a raw env string", () => {
  const prev = process.env.APINJ_CONSENT_TIMEOUT_S;
  try {
    process.env.APINJ_CONSENT_TIMEOUT_S = "7";
    for (const s of [buildDialogScript("https://x.com", "u"), buildSecretDialogScript("https://x.com", "n"), buildKindDialogScript("sms_code", "https://x.com")]) {
      expect(s).toEndWith("giving up after 7");
    }
    process.env.APINJ_CONSENT_TIMEOUT_S = '5" & do shell script "touch /tmp/x';
    expect(buildDialogScript("https://x.com", "u")).toEndWith("giving up after 25");
  } finally {
    if (prev === undefined) delete process.env.APINJ_CONSENT_TIMEOUT_S; else process.env.APINJ_CONSENT_TIMEOUT_S = prev;
  }
});

test("parseConsent: Allow, Deny, and the dialog giving up are three different answers", () => {
  expect(parseConsent("button returned:Allow, gave up:false\n")).toBe("allow");
  expect(parseConsent("button returned:Deny, gave up:false\n")).toBe("deny");
  expect(parseConsent("button returned:, gave up:true\n")).toBe("timeout");
  expect(parseConsent("")).toBe("deny");
  expect(parseConsent(undefined)).toBe("deny");
});

function shim(body: string) {
  const dir = mkdtempSync(join(tmpdir(), "apinj-osa-"));
  const bin = join(dir, "osascript");
  writeFileSync(bin, `#!/bin/bash\n${body}\n`);
  chmodSync(bin, 0o755);
  return { dir, bin };
}

test("the real runner is async: timers fire while the dialog is open", async () => {
  const { dir, bin } = shim(`sleep 0.6; echo "button returned:Allow, gave up:false"`);
  try {
    let tickedAt = 0;
    const t0 = performance.now();
    setTimeout(() => { tickedAt = performance.now() - t0; }, 50);
    const r = await confirmInjection("https://x.com", "u", "x.com", osascriptRunner(bin));
    const doneAt = performance.now() - t0;
    expect(r).toBe("allow");
    expect(tickedAt).toBeGreaterThan(0);
    expect(tickedAt).toBeLessThan(doneAt - 300); // the timer did not wait for the dialog
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a cancelled request kills the dialog process and answers `cancelled`", async () => {
  const { dir, bin } = shim(`sleep 1; touch "$(dirname "$0")/answered"; echo "button returned:Allow, gave up:false"`);
  try {
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 100);
    const t0 = performance.now();
    const r = await runWithRequestSignal(ac.signal, () => confirmInjection("https://x.com", "u", "x.com", osascriptRunner(bin)));
    expect(r).toBe("cancelled");
    expect(performance.now() - t0).toBeLessThan(800);
    await new Promise((ok) => setTimeout(ok, 1200));
    expect(existsSync(join(dir, "answered"))).toBe(false); // the shell never got to answer
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("an answer that arrives after cancellation is dropped, even a synchronous Allow", async () => {
  const ac = new AbortController();
  const r = await runWithRequestSignal(ac.signal, () =>
    confirmInjection("https://x.com", "u", "x.com", () => { ac.abort(); return "button returned:Allow, gave up:false"; }));
  expect(r).toBe("cancelled");
});

// ── The gate ─────────────────────────────────────────────────────────────────

function gateHarness() {
  const typed: string[] = [];
  const send = (async () => ({})) as unknown as Send;
  const d: GateDeps = {
    resolveTarget: async () => ({ wsUrl: "ws://stub", url: "https://x.com/" }),
    withConn: async (_ws, fn) => fn(send),
    getOrigin: async () => "https://x.com",
    getLoaderId: async () => "L1",
  };
  const run = async (_s: Send, guard: () => Promise<void>) => { await guard(); typed.push("secret"); return { filled: true }; };
  return { d, typed, run };
}

test("gate: a dialog that gave up is `consent_timeout`, and nothing is typed", async () => {
  const h = gateHarness();
  expect(await gatedOnOrigin(h.d, "T", "https://x.com", async () => "timeout", h.run)).toEqual({ filled: false, reason: "consent_timeout" });
  expect(h.typed).toEqual([]);
});

test("gate: Deny stays `user_denied`; true and `allow` both fill", async () => {
  const h = gateHarness();
  expect(await gatedOnOrigin(h.d, "T", "https://x.com", async () => "deny", h.run)).toEqual({ filled: false, reason: "user_denied" });
  expect(await gatedOnOrigin(h.d, "T", "https://x.com", async () => false, h.run)).toEqual({ filled: false, reason: "user_denied" });
  expect(await gatedOnOrigin(h.d, "T", "https://x.com", async () => "allow", h.run)).toEqual({ filled: true });
  expect(await gatedOnOrigin(h.d, "T", "https://x.com", async () => true, h.run)).toEqual({ filled: true });
  expect(h.typed.length).toBe(2);
});

test("gate: an Allow after the request was cancelled types nothing", async () => {
  const h = gateHarness();
  const ac = new AbortController();
  const r = await runWithRequestSignal(ac.signal, () =>
    gatedOnOrigin(h.d, "T", "https://x.com", async () => { ac.abort(); return true; }, h.run));
  expect(r).toEqual({ filled: false, reason: "request_cancelled" });
  expect(h.typed).toEqual([]);
});

test("gate: cancellation between consent and the keystroke is caught by the guard", async () => {
  const h = gateHarness();
  const ac = new AbortController();
  const r = await runWithRequestSignal(ac.signal, () =>
    gatedOnOrigin(h.d, "T", "https://x.com", async () => true, async (s, guard) => {
      ac.abort(); // e.g. the caller gives up while the code wait is polling
      return h.run(s, guard);
    }));
  expect(r).toEqual({ filled: false, reason: "request_cancelled" });
  expect(h.typed).toEqual([]);
});

test("gate: one call's cancellation does not reach a concurrent call", async () => {
  const a = gateHarness();
  const b = gateHarness();
  const acA = new AbortController();
  const acB = new AbortController();
  const slow = (fn: () => void) => async () => { await new Promise((ok) => setTimeout(ok, 50)); fn(); return true; };
  const [ra, rb] = await Promise.all([
    runWithRequestSignal(acA.signal, () => gatedOnOrigin(a.d, "T", "https://x.com", slow(() => acA.abort()), a.run)),
    runWithRequestSignal(acB.signal, () => gatedOnOrigin(b.d, "T", "https://x.com", slow(() => {}), b.run)),
  ]);
  expect(ra).toEqual({ filled: false, reason: "request_cancelled" });
  expect(rb).toEqual({ filled: true });
  expect(b.typed).toEqual(["secret"]);
});
