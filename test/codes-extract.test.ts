import { describe, expect, test } from "bun:test";
import { extractCode } from "../src/codes/extract.ts";

const H = "example.com";

describe("extractCode", () => {
  const cases: [string, string, string | null][] = [
    ["bank", "Chase: Your verification code is 482913. Do not share it with anyone.", "482913"],
    ["github", "Your GitHub launch code is 731904\nVisit https://github.com/login/device", "731904"],
    ["google G-code", "G-204518 is your Google verification code.", "204518"],
    ["code after number", "834120 is your security code for Acme.", "834120"],
    ["otp word", "Use OTP 5521 to sign in to your account. Valid 10 minutes.", "5521"],
    ["8 digit", "Your passcode: 90817263", "90817263"],
    ["dashed 3-3", "Your login code is 123-456. Expires soon.", "123456"],
    ["promo no code", "Big sale! Save 20% on everything this weekend. Reply STOP to opt out.", null],
    ["dollar amount", "You spent $1250.00 at Store. Your one-time code is 664201.", "664201"],
    ["amount only", "Payment of $4500 received, thank you.", null],
    ["time ignored", "Your code 335577 expires at 10:30 today", "335577"],
    ["year deprioritized", "In 2024 your verification code is 918273", "918273"],
    ["two non-adjacent", "Order 445566 shipped, tracking 778899 for you.", null],
    ["phone number ignored", "Call us at 555-123-4567. Your PIN is 4821.", "4821"],
    ["webotp match", "Your code is 123456\n\n@example.com #123456", "123456"],
    ["webotp case-insens", "<#> 998877 is your code\n@Example.COM #998877", "998877"],
    ["webotp mismatch", "Your code is 123456\n\n@evil.example.net #123456", null],
    ["empty", "", null],
  ];
  for (const [name, body, want] of cases) {
    test(name, () => expect(extractCode(body, H)).toBe(want));
  }

  test("webotp host with surrounding whitespace on tabHost", () => {
    expect(extractCode("x\n@example.com #424242", " example.com ")).toBe("424242");
  });
});
