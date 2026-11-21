// Pull a one-time code out of a message body. Pure; never logs.

const KEYWORD =
  /(verification|passcode|one[- ]time|security|sign[- ]?in|log[- ]?in|code|otp|pin)/gi;
const PROXIMITY = 40;

interface Cand { digits: string; start: number; end: number }

function webOtp(body: string): { host: string; code: string } | null {
  const lines = body.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const last = lines[lines.length - 1];
  if (!last) return null;
  const m = /^@([A-Za-z0-9.-]+)\s+#(\S+)$/.exec(last);
  return m ? { host: m[1]!.toLowerCase(), code: m[2]! } : null;
}

function candidates(body: string): Cand[] {
  const out: Cand[] = [];
  const re = /(?<![\w$.,:+-])(?:[A-Za-z]-)?(\d{3}[- ]?\d{3}|\d{4,8})(?![\w.,:%]\d|\w)/g;
  for (const m of body.matchAll(re)) {
    const digits = m[1]!.replace(/[- ]/g, "");
    if (digits.length < 4 || digits.length > 8) continue;
    const start = m.index!;
    const end = start + m[0].length;
    const before = body.slice(Math.max(0, start - 2), start);
    const after = body.slice(end, end + 3);
    if (/\$\s?$/.test(before) || /^[.,]\d/.test(after) || /^\s?(%|USD|dollars)/i.test(after)) continue; // amounts
    if (/^:\d\d/.test(after) || /\d:$/.test(body.slice(Math.max(0, start - 1), start))) continue; // times
    if (/^\s?(AM|PM)\b/i.test(after)) continue;
    // phone numbers: dashed/spaced 3-3 groups next to other digit groups, or leading + / parens
    const ctx = body.slice(Math.max(0, start - 6), end + 6);
    if (/\(\d{3}\)\s?\d{3}[- ]\d{4}/.test(ctx) || /\d{3}[- ]\d{3}[- ]\d{4}/.test(ctx) || /\+\d[\d\s-]{6,}/.test(ctx)) continue;
    if (/\d{3}-\d{4}/.test(body.slice(start, end + 5)) && /[- ]/.test(m[1]!)) continue;
    out.push({ digits, start, end });
  }
  return out;
}

function keywordAdjacent(body: string, c: Cand): boolean {
  const win = body.slice(Math.max(0, c.start - PROXIMITY), c.end + PROXIMITY);
  KEYWORD.lastIndex = 0;
  return KEYWORD.test(win);
}

export function extractCode(body: string, tabHost: string): string | null {
  const w = webOtp(body);
  if (w) return w.host === tabHost.trim().toLowerCase() ? w.code : null;

  const all = candidates(body);
  if (all.length === 0) return null;
  const isYear = (c: Cand) => /^(19|20)\d\d$/.test(c.digits);
  const near = all.filter((c) => keywordAdjacent(body, c));
  const pool = (list: Cand[]) => {
    const better = list.filter((c) => !isYear(c));
    return better.length ? better : list;
  };
  const distinct = (list: Cand[]) => [...new Set(list.map((c) => c.digits))];

  if (near.length) {
    const d = distinct(pool(near));
    if (d.length === 1) return d[0]!;
    // several keyword-adjacent: take the one closest after a keyword
    let best: { d: string; dist: number } | null = null;
    for (const c of pool(near)) {
      KEYWORD.lastIndex = 0;
      for (const k of body.matchAll(KEYWORD)) {
        const kEnd = k.index! + k[0].length;
        const dist = c.start >= kEnd ? c.start - kEnd : k.index! - c.end + 1000;
        if (!best || dist < best.dist) best = { d: c.digits, dist };
      }
    }
    return best ? best.d : null;
  }
  // No keyword anywhere near any number: refuse. An order number or a ZIP from
  // the bound site is not a sign-in code, and typing a guess is worse than
  // reporting `no_code`.
  return null;
}
