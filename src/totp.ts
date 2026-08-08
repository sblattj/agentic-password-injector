import { createHmac } from "node:crypto";

function b32decode(s: string): Buffer {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  const out: number[] = [];
  for (const c of s.replace(/=+$/, "").toUpperCase()) {
    const v = alpha.indexOf(c);
    if (v < 0) continue;
    bits += v.toString(2).padStart(5, "0");
  }
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

export function totpCode(base32Seed: string, at: number = Math.floor(Date.now() / 1000)): string {
  const counter = Math.floor(at / 30);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const hmac = createHmac("sha1", b32decode(base32Seed)).update(buf).digest();
  const off = hmac[hmac.length - 1] & 0xf;
  const bin = ((hmac[off] & 0x7f) << 24) | (hmac[off + 1] << 16) | (hmac[off + 2] << 8) | hmac[off + 3];
  return (bin % 1_000_000).toString().padStart(6, "0");
}
