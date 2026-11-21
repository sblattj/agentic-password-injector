// Entry-point validators shared by tools.ts and the passkey / code tools.

const SECRET_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
export function isValidSecretName(raw: string): boolean {
  return SECRET_NAME_RE.test(raw);
}


const LOCAL_HTTP_HOSTS = new Set(["localhost", "127.0.0.1"]);

/**
 * The origin the new entry is BOUND to, normalised to `scheme://host[:port]`.
 * https only, except plain http to the loopback names. Anything else is null.
 * The result is ASCII with no spaces or quotes (WHATWG URL serialisation), so it
 * survives `parseComment` unchanged.
 */
export function normalizeSaveOrigin(raw: unknown): string | null {
  if (typeof raw !== "string" || !raw || raw.length > 2048) return null;
  let u: URL;
  try { u = new URL(raw); } catch { return null; }
  if (u.protocol === "https:") { /* ok */ }
  else if (u.protocol === "http:" && LOCAL_HTTP_HOSTS.has(u.hostname)) { /* ok */ }
  else return null;
  if (!u.hostname) return null;
  const o = u.origin;
  return /^[\x21-\x7e]+$/.test(o) && !/["\\]/.test(o) ? o : null;
}

