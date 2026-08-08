import { originMatches } from "./origin.ts";

/**
 * The security gate. Pure and total: no I/O, no secrets, no side effects.
 *
 * ORDER IS LOAD-BEARING. Origin-match is evaluated FIRST so that a tab whose live
 * origin does not match the saved credential's origin is refused with
 * `origin_mismatch` regardless of what the user answered. Callers must ALSO
 * short-circuit before showing the consent dialog (see tools.ts) so a mismatched
 * tab can never even prompt — this function is the second, authoritative check.
 */
export function decideGate(i: { tabOrigin: string; savedOrigin: string; allow: boolean }):
  | { ok: true }
  | { ok: false; reason: string } {
  if (!originMatches(i.tabOrigin, i.savedOrigin)) return { ok: false, reason: "origin_mismatch" };
  if (!i.allow) return { ok: false, reason: "user_denied" };
  return { ok: true };
}
