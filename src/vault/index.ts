import { arcLookup, vivaldiLookup, type Cred } from "./arc.ts";
import { keychainLookup } from "./keychain.ts";

type Backends = {
  /** Optional so a caller can chain a subset; production wires all three. */
  vivaldi?: (d: string, opts: { name?: string }) => Promise<Cred | null>;
  arc: (d: string, opts: { name?: string }) => Promise<Cred | null>;
  keychain: (n: string) => Promise<Cred | null>;
};
export type Resolved = { cred: Cred; backend: "vivaldi" | "arc" | "keychain" } | { found: false; tried: string[] };

/**
 * Resolution order is Vivaldi, then Arc, then Keychain, with two rules the caller depends on:
 *
 * 1. `name` SELECTS. When it is supplied the returned credential must be the one
 *    the name identifies: a browser row whose username is `name`, or the Keychain
 *    entry stored under `apinj:<name>`. Returning a domain-matched credential
 *    with a different identity is worse than returning nothing: the consent
 *    dialog then shows the wrong username and the wrong account is typed in.
 *    So a supplied `name` that matches nothing is a MISS, never a substitution.
 *    The `c.username !== name` re-check below is deliberate belt-and-braces: it
 *    holds even if a backend ignores the `name` it was handed.
 *
 * 2. A browser-store FAULT is not fatal to the chain (M5). A locked or unreadable
 *    store must not hide a credential in a later store. The first fault is
 *    remembered and re-thrown if every backend misses, so a locked vault never
 *    degrades into `not_found`, the fault-reads-as-miss shape invariant #3 forbids.
 *    A browser that is not installed is a MISS, not a fault.
 */
export async function resolveCredentialWith(b: Backends, domain: string, opts: { name?: string }): Promise<Resolved> {
  const name = opts.name;
  const tried: string[] = [];
  let fault: unknown = null;

  const stores: ["vivaldi" | "arc", ((d: string, o: { name?: string }) => Promise<Cred | null>) | undefined][] = [["vivaldi", b.vivaldi], ["arc", b.arc]];
  for (const [label, lookup] of stores) {
    if (!lookup) continue;
    tried.push(label);
    let c: Cred | null = null;
    try { c = await lookup(domain, { name }); }
    catch (e) { fault ??= e; }
    if (c && (!name || c.username === name)) return { cred: c, backend: label };
  }

  // The Keychain is keyed by ENTRY name, so `name` selects here by construction:
  // a hit under `apinj:<name>` IS the named credential, whatever its username.
  tried.push("keychain");
  const k = await b.keychain(name ?? domain);
  if (k) return { cred: k, backend: "keychain" };

  if (fault) throw fault;
  return { found: false, tried };
}

export function resolveCredential(domain: string, opts: { name?: string } = {}): Promise<Resolved> {
  return resolveCredentialWith({ vivaldi: (d, o) => vivaldiLookup(d, {}, o), arc: (d, o) => arcLookup(d, {}, o), keychain: keychainLookup }, domain, opts);
}
