import { expect, test } from "bun:test";
import { totpCode } from "../src/totp.ts";

// RFC 6238 SHA1 seed "12345678901234567890" = base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; at T=59 -> 94287082 (low 6 digits = 287082)
test("RFC 6238 vector", () => {
  expect(totpCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59)).toBe("287082");
});

// RFC 6238 SHA1 vector at T=1111111109 -> 07081804 (low 6 digits = 081804); exercises the counter path.
test("RFC 6238 vector T=1111111109", () => {
  expect(totpCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1111111109)).toBe("081804");
});

// RFC 6238 SHA1 vector at T=1234567890 -> 89005924 (low 6 digits = 005924, per RFC 6238 Appendix B table);
// exercises the counter > 2^32 / high-word path that the T=59 vector does not.
test("RFC 6238 vector T=1234567890", () => {
  expect(totpCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1234567890)).toBe("005924");
});
