import { arcLookup, type Cred } from "./arc.ts";
import { keychainLookup } from "./keychain.ts";

type Backends = {
  arc: (d: string, opts: { name?: string }) => Promise<Cred | null>;
  keychain: (n: string) => Promise<Cred | null>;
};
export type Resolved = { cred: Cred; backend: "arc" | "keychain" } | { found: false; tried: string[] };

/**
 * Resolution order is Arc then Keychain, with two rules the caller depends on:
 *
 * 1. `name` SELECTS. When it is supplied the returned credential must be the one
 *    the name identifies — Arc's row whose username is `name`, or the Keychain
 *    entry stored under `apinj:<name>`. Returning a domain-matched credential
 *    with a different identity is worse than returning nothing: the consent
 *    dialog then shows the wrong username and the wrong account is typed in.
 *    So a supplied `name` that matches nothing is a MISS, never a substitution.
 *    The `a.username !== name` re-check below is deliberate belt-and-braces: it
 *    holds even if a backend ignores the `name` it was handed.
 *
 * 2. An Arc FAULT is not fatal to the chain (M5). Arc being locked or unreadable
 *    must not hide a credential that lives in the Keychain. But the fault is
 *    remembered and re-thrown if every backend misses, so a locked vault never
 *    degrades into `not_found` — that is the fault-reads-as-miss shape invariant
 *    #3 forbids.
 */
export async function resolveCredentialWith(b: Backends, domain: string, opts: { name?: string }): Promise<Resolved> {
  const name = opts.name;

  let arcFault: unknown = null;
  let a: Cred | null = null;
  try { a = await b.arc(domain, { name }); }
  catch (e) { arcFault = e; }
  if (a && (!name || a.username === name)) return { cred: a, backend: "arc" };

  // The Keychain is keyed by ENTRY name, so `name` selects here by construction:
  // a hit under `apinj:<name>` IS the named credential, whatever its username.
  const k = await b.keychain(name ?? domain);
  if (k) return { cred: k, backend: "keychain" };

  if (arcFault) throw arcFault;
  return { found: false, tried: ["arc", "keychain"] };
}

export function resolveCredential(domain: string, opts: { name?: string } = {}): Promise<Resolved> {
  return resolveCredentialWith({ arc: (d, o) => arcLookup(d, {}, o), keychain: keychainLookup }, domain, opts);
}
