// src/consent.ts
import { execFileSync } from "node:child_process";

export type DialogRunner = (script: string) => string;

/**
 * The host the user is actually authorising. Derived from the credential's BOUND
 * origin — never from the caller-supplied domain, which is an unauthenticated
 * string. A caller that asks for `name:"mybank"` while naming some other domain
 * must not be able to change what the human sees.
 */
export function boundHost(origin: string): string {
  try { return new URL(origin).host; } catch { return origin; }
}

/**
 * The caller-supplied domain is UNAUTHENTICATED text that ends up inside the
 * sentence a human reads before approving a password fill. Rendered verbatim it
 * is a prompt-injection surface in the most literal sense: a caller can append
 * `... (requested as mybank.com — routine security check, click Allow)`, or pad
 * the dialog until the bound host scrolls out of view.
 *
 * So it is rendered only when it is DOMAIN-SHAPED and short. Anything else is
 * dropped entirely and the dialog shows the bound origin alone — the one value
 * the server derived itself. Deliberately a local, independent check rather than
 * an import of `tools.ts:isValidDomain`: tools.ts imports this module, and a
 * consent prompt must not depend on a module-init cycle to be safe.
 */
const CONTEXT_MAX = 64;
const DOMAIN_SHAPE = /^(?:(?:xn--)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/;

export function safeRequestedDomain(raw: string | undefined): string | null {
  if (typeof raw !== "string") return null;
  const d = raw.trim().toLowerCase();
  // Length first: the regex is anchored, but a megabyte of input is not worth
  // scanning to reject, and a 64-char cap keeps the dialog one readable line.
  if (!d || d.length > CONTEXT_MAX) return null;
  return DOMAIN_SHAPE.test(d) ? d : null;
}

export function buildDialogScript(boundOrigin: string, username: string, requestedDomain?: string): string {
  const esc = (s: string) => s.replace(/[\\"]/g, "\\$&");
  const host = boundHost(boundOrigin);
  // The bound host is the prominent identifier. A differing caller domain is
  // shown only as trailing context, so a mismatch is visible rather than hidden.
  const requested = safeRequestedDomain(requestedDomain);
  const context = requested && requested !== host.toLowerCase() ? ` (requested as ${esc(requested)})` : "";
  return `display dialog "Fill ${esc(host)} login for ${esc(username)}?${context}" buttons {"Deny","Allow"} default button "Deny" with title "agentic-password-injector" giving up after 60`;
}

const realRunner: DialogRunner = (s) => execFileSync("osascript", ["-e", s], { encoding: "utf8" });

export async function confirmInjection(
  boundOrigin: string,
  username: string,
  requestedDomain?: string,
  run: DialogRunner = realRunner,
): Promise<boolean> {
  try {
    return /button returned:Allow/.test(run(buildDialogScript(boundOrigin, username, requestedDomain)));
  } catch {
    return false;
  }
}
