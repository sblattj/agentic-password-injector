import { expect, test } from "bun:test";
import { SECRET_FORMATS, isSecretFormat, shape } from "../src/secret.ts";
import { CdpError } from "../src/cdp.ts";

const SSN = "123456789";

test("raw returns the stored value verbatim, whatever it looks like", () => {
  expect(shape(SSN, "raw")).toBe(SSN);
  expect(shape("Tr0ub4dor&3 with spaces", "raw")).toBe("Tr0ub4dor&3 with spaces");
  expect(shape("", "raw")).toBe("");
});

test("the four field shapes seen in the wild", () => {
  expect(shape(SSN, "dashed")).toBe("123-45-6789"); // one box, dashes typed
  expect(shape(SSN, "last4")).toBe("6789");         // "last four digits" box
  expect(shape(SSN, "first3")).toBe("123");         // segmented, three boxes
  expect(shape(SSN, "mid2")).toBe("45");            // segmented, three boxes
});

test("a stored value that is ALREADY dashed shapes identically", () => {
  // Non-digits are stripped before the count, so how the human chose to store it
  // does not change what the field receives.
  for (const stored of ["123-45-6789", "123 45 6789", " 123456789 "]) {
    expect(shape(stored, "dashed")).toBe("123-45-6789");
    expect(shape(stored, "last4")).toBe("6789");
  }
});

// ── The assertion that stops a shaper degrading into the identity function ───
//
// `last4` on a four-digit stored value returns the whole value; `first3` on a
// three-digit one returns the whole value. Both would report filled:true having
// typed the ENTIRE secret into a box authorised for a fragment of it.

test("every non-raw format REFUSES a value that is not nine digits", () => {
  for (const fmt of ["dashed", "last4", "first3", "mid2"] as const) {
    for (const bad of ["6789", "123", "45", "", "12345678", "1234567890", "no-digits-here"]) {
      let err: any;
      try { shape(bad, fmt); } catch (e) { err = e; }
      expect(err).toBeInstanceOf(CdpError);
      expect(err.code).toBe("format_mismatch");
    }
  }
});

test("the refusal is not vacuous: last4 on a 4-digit value would have returned all of it", () => {
  // Proves the guard above is what prevents the whole-secret send, rather than
  // some other accident of the implementation.
  const naiveLast4 = (v: string) => v.replace(/\D/g, "").slice(5) || v.replace(/\D/g, "");
  expect(naiveLast4("6789")).toBe("6789"); // ← the entire stored value
  expect(() => shape("6789", "last4")).toThrow("format_mismatch");
});

test("the refusal message carries no digit COUNT and no fragment of the value", () => {
  // Secrecy is a property of the FORMAT, not the length: a reason string that
  // says "found 4 digits" leaks a property of the secret into the model's
  // context, and the reason vocabulary is exactly what the model reads.
  let err: any;
  try { shape("6789", "last4"); } catch (e) { err = e; }
  const msg = String(err?.message ?? "");
  expect(msg).not.toContain("6789");
  expect(msg).not.toMatch(/\d/);
});

test("raw is exempt from the assertion — a generated password has no digit count", () => {
  expect(() => shape("Tr0ub4dor&3", "raw")).not.toThrow();
});

test("isSecretFormat accepts exactly the five formats and nothing else", () => {
  for (const f of SECRET_FORMATS) expect(isSecretFormat(f)).toBe(true);
  for (const bad of ["", "RAW", "dash", "last-4", "toString", null, undefined, 1, {}]) {
    expect(isSecretFormat(bad)).toBe(false);
  }
});

test("an unvalidated format string throws rather than falling through to the whole secret", () => {
  // The one branch `isSecretFormat` is supposed to make unreachable. If a caller
  // ever skips it, the failure must be a refusal, not a full-value send.
  let err: any;
  try { shape(SSN, "sneaky" as any); } catch (e) { err = e; }
  expect(err?.code).toBe("bad_format");       // nine digits, so it reaches the switch
  try { shape("abc", "sneaky" as any); } catch (e) { err = e; }
  expect(err?.code).toBe("format_mismatch");  // the digit gate refuses first
});

test("shape never returns MORE than the stored value's digits for a fragment format", () => {
  for (const fmt of ["last4", "first3", "mid2"] as const) {
    expect(shape(SSN, fmt).length).toBeLessThan(SSN.length);
  }
});
