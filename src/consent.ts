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

/**
 * The entry name a named secret is stored under, as it may appear in the dialog.
 *
 * Same threat as `safeRequestedDomain`: the name arrives from the caller and
 * lands inside the sentence a human reads before approving. A name is
 * `[a-z0-9]` plus `.`, `_` and `-`, capped at 64 — no whitespace, so it cannot
 * grow prose; no quotes or backslashes, so it cannot restructure the AppleScript
 * string; no control characters, so it cannot push the bound host off the
 * dialog. Deliberately a local, independent check, mirroring the one at the tool
 * entry point: neither is allowed to be the only guard.
 */
const NAME_SHAPE = /^[a-z0-9][a-z0-9._-]{0,63}$/i;

export function safeSecretName(raw: string | undefined): string | null {
  if (typeof raw !== "string") return null;
  return NAME_SHAPE.test(raw) ? raw : null;
}

/**
 * "Type ssn-full into forms.example.com?" is a materially different question from
 * "log in to forms.example.com", so the secret's dialog names WHAT is being typed as
 * well as where. The entry name is the only handle a human has on a value they
 * are never shown — without it, every secret on a site raises an identical
 * prompt and consent stops carrying information.
 *
 * A name that fails the shape check is dropped rather than rendered; the bound
 * host, which the server derived itself, always survives.
 */
export function buildSecretDialogScript(boundOrigin: string, secretName?: string): string {
  const esc = (s: string) => s.replace(/[\\"]/g, "\\$&");
  const host = boundHost(boundOrigin);
  const name = safeSecretName(secretName);
  const what = name ? `secret '${esc(name)}'` : "a saved secret";
  return `display dialog "Type ${what} into ${esc(host)}?" buttons {"Deny","Allow"} default button "Deny" with title "agentic-password-injector" giving up after 60`;
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

export async function confirmSecretInjection(
  boundOrigin: string,
  secretName: string,
  run: DialogRunner = realRunner,
): Promise<boolean> {
  try {
    return /button returned:Allow/.test(run(buildSecretDialogScript(boundOrigin, secretName)));
  } catch {
    return false;
  }
}
