import { CdpError } from "./cdp.ts";

/**
 * Shaping a stored secret into the form a particular field demands.
 *
 * Real identity forms want the same nine digits in five different shapes, and a
 * caller that reshapes them itself has, by definition, seen them. So the shaping
 * happens HERE — after the vault read, before the keystroke, inside the process
 * that already holds the plaintext. Pure and I/O-free so the 9-digit assertion
 * below is trivially testable.
 */
export const SECRET_FORMATS = ["raw", "dashed", "last4", "first3", "mid2"] as const;
export type SecretFormat = (typeof SECRET_FORMATS)[number];

export function isSecretFormat(v: unknown): v is SecretFormat {
  return typeof v === "string" && (SECRET_FORMATS as readonly string[]).includes(v);
}

/**
 * SECURITY: every format except `raw` ASSERTS exactly nine digits and refuses
 * rather than sending.
 *
 * Without the assertion `last4` on a four-digit stored value returns the whole
 * value, `first3` on a three-digit one returns the whole value, and the tool
 * reports `filled:true` having typed the entire secret into a box that was only
 * ever authorised to receive a fragment of it. The shapes below exist precisely
 * because the field wants LESS than the secret; a shaper that can degrade to the
 * identity function is not a shaper.
 *
 * The refusal carries no digit count. "How many digits does the stored value
 * have" is a property of the secret, and the reason vocabulary is read by the
 * model — see the masking note in docs/handoff-named-secrets.md, where a length
 * test leaked the tail of a dashed SSN twice in one day.
 */
export function shape(value: string, format: SecretFormat): string {
  if (format === "raw") return value;
  const digits = value.replace(/\D/g, "");
  if (digits.length !== 9) {
    throw new CdpError("format_mismatch", "stored value is not a nine-digit number");
  }
  switch (format) {
    case "dashed": return `${digits.slice(0, 3)}-${digits.slice(3, 5)}-${digits.slice(5)}`;
    case "last4": return digits.slice(5);
    // Segmented inputs: some forms split an SSN across three boxes, twice over.
    case "first3": return digits.slice(0, 3);
    case "mid2": return digits.slice(3, 5);
  }
  // Unreachable for a SecretFormat, but a caller that skipped `isSecretFormat`
  // must not fall through to "return the whole secret".
  throw new CdpError("bad_format", "unknown secret format");
}
