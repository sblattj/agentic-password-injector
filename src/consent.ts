// src/consent.ts
import { execFile } from "node:child_process";
import { requestCancelled, requestSignal } from "./request.ts";

/**
 * Shows one dialog and returns what osascript printed. May be async: the real
 * runner is (issue #1), so the server keeps answering `tools/list` and health
 * checks while a human looks at the prompt.
 */
export type DialogRunner = (script: string, signal?: AbortSignal) => string | Promise<string>;

/**
 * What the human did with an Allow/Deny prompt. `timeout` is the dialog giving
 * up on its own; `cancelled` is the MCP request going away while it was open.
 * Only `allow` lets a fill proceed.
 */
export type ConsentOutcome = "allow" | "deny" | "timeout" | "cancelled";

/**
 * How long an Allow/Deny dialog waits before giving up, in seconds (issue #1).
 *
 * Default 25: below the ~30 s many MCP gateways and proxies allow a backend tool
 * call, so an unanswered prompt comes back as a clean `consent_timeout` instead
 * of a transport error. `APINJ_CONSENT_TIMEOUT_S` overrides it (a whole number,
 * 1 to 600); anything else falls back to the default. The value is parsed to an
 * integer before it reaches the AppleScript, so env text is never interpolated.
 * Read on every call, like `dialogRequired`.
 */
export const CONSENT_TIMEOUT_DEFAULT_S = 25;
export const CONSENT_TIMEOUT_MAX_S = 600;

export function consentTimeoutS(env: Record<string, string | undefined> = process.env): number {
  const raw = (env.APINJ_CONSENT_TIMEOUT_S ?? "").trim();
  if (!/^\d{1,4}$/.test(raw)) return CONSENT_TIMEOUT_DEFAULT_S;
  const n = Number(raw);
  return n >= 1 && n <= CONSENT_TIMEOUT_MAX_S ? n : CONSENT_TIMEOUT_DEFAULT_S;
}

/** Maps osascript's output to an outcome. `gave up:true` is what `giving up after N` prints. */
export function parseConsent(out: unknown): ConsentOutcome {
  const s = typeof out === "string" ? out : "";
  if (/button returned:Allow/.test(s)) return "allow";
  if (/gave up:true/.test(s)) return "timeout";
  return "deny";
}

async function ask(script: string, run: DialogRunner): Promise<ConsentOutcome> {
  try {
    const out = await run(script, requestSignal());
    // The answer arrived, but the caller is already gone: a late Allow is dropped.
    return requestCancelled() ? "cancelled" : parseConsent(out);
  } catch {
    return requestCancelled() ? "cancelled" : "deny";
  }
}

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
  return `display dialog "Fill ${esc(host)} login for ${esc(username)}?${context}" buttons {"Deny","Allow"} default button "Deny" with title "agentic-password-injector" giving up after ${consentTimeoutS()}`;
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
  return `display dialog "Type ${what} into ${esc(host)}?" buttons {"Deny","Allow"} default button "Deny" with title "agentic-password-injector" giving up after ${consentTimeoutS()}`;
}

/**
 * Passkey and one-time-code prompts. Same rules as the secret dialog: the bound
 * host is the server's own value, and the entry name survives only if it passes
 * `safeSecretName`. `what` is a fixed vocabulary chosen by the server, never
 * caller text.
 */
export type PromptKind = "passkey_register" | "passkey_login" | "sms_code" | "email_code";

export function buildKindDialogScript(kind: PromptKind, boundOrigin: string, entryName?: string): string {
  const esc = (s: string) => s.replace(/[\\"]/g, "\\$&");
  const host = esc(boundHost(boundOrigin));
  const name = safeSecretName(entryName);
  const entry = name ? ` (entry '${esc(name)}')` : "";
  const text =
    kind === "passkey_register" ? `Create an agent passkey for ${host}${entry}?` :
    kind === "passkey_login" ? `Sign in to ${host} with the agent passkey${entry}?` :
    kind === "sms_code" ? `Type the newest text-message code into ${host}?` :
    `Type the newest email code into ${host}?`;
  return `display dialog "${text}" buttons {"Deny","Allow"} default button "Deny" with title "agentic-password-injector" giving up after ${consentTimeoutS()}`;
}

export async function confirmKind(
  kind: PromptKind,
  boundOrigin: string,
  entryName?: string,
  run: DialogRunner = realRunner,
): Promise<ConsentOutcome> {
  return ask(buildKindDialogScript(kind, boundOrigin, entryName), run);
}

/**
 * Whether a fill raises the Allow/Deny dialog at all. Off by default: every fill
 * is auto-approved, and the protections that do not need a human (mandatory
 * origin binding, the pre-keystroke `loaderId` guard) still run. Set
 * `APINJ_CONFIRM=1` (or `true`/`yes`/`on`) to get the per-use dialog back for
 * both credentials and named secrets. Read on every call, so a restart is not
 * needed to pick up a change in a long-lived env.
 */
export function dialogRequired(env: Record<string, string | undefined> = process.env): boolean {
  return /^(1|true|yes|on)$/i.test((env.APINJ_CONFIRM ?? "").trim());
}

/**
 * The real dialog: `osascript`, run ASYNC (issue #1). `execFileSync` froze the
 * event loop for as long as the dialog was up, so the server could not answer
 * `tools/list` or a health probe and a gateway marked it unhealthy.
 *
 * On abort (the MCP request was cancelled, or the transport closed) the child
 * is killed, which takes its dialog down with it, and the call rejects; the
 * callers map that to `cancelled`. A backstop timeout a little past the
 * script's own `giving up after N` kills a child that never returns.
 */
export function osascriptRunner(bin = "osascript"): DialogRunner {
  return (script, signal) => new Promise<string>((ok, err) => {
    const m = script.match(/giving up after (\d+)/);
    const backstopMs = ((m ? Number(m[1]) : CONSENT_TIMEOUT_DEFAULT_S) + 10) * 1000;
    execFile(bin, ["-e", script], { encoding: "utf8", signal, timeout: backstopMs, killSignal: "SIGKILL" }, (e, stdout) => {
      // The error object is never read: for the save dialog it sits next to a secret.
      if (e) err(new Error("dialog_failed")); else ok(stdout);
    });
  });
}

const realRunner: DialogRunner = osascriptRunner();

/**
 * The `save_credential` prompt: a human types (or pastes) the password into a
 * HIDDEN answer field, and only `text returned` comes back, so the button name
 * never mixes with the secret.
 *
 * Every caller value is checked again here before it lands in the sentence: the
 * origin is reduced to its host, the name must pass `safeSecretName`, and the
 * username has quotes, backslashes and control characters stripped for DISPLAY
 * (the tool refuses such usernames anyway; this is the second guard).
 */
export const SAVE_DIALOG_TIMEOUT_S = 120;

export function displayUsername(raw: string): string {
  return raw.replace(/[\x00-\x1f\x7f"\\]/g, "").slice(0, 128);
}

export function buildSavePasswordDialogScript(origin: string, username: string, name: string): string {
  const esc = (s: string) => s.replace(/[\\"]/g, "\\$&");
  const host = boundHost(origin);
  const entry = safeSecretName(name) ?? "unnamed";
  const text = `Save a login for ${esc(host)} as ${esc(displayUsername(username))} (entry '${esc(entry)}')? Paste the password:`;
  return `text returned of (display dialog "${text}" default answer "" with hidden answer ` +
    `buttons {"Cancel","Save"} default button "Save" cancel button "Cancel" ` +
    `with title "agentic-password-injector" giving up after ${SAVE_DIALOG_TIMEOUT_S})`;
}

/**
 * Returns the typed password, or null for Cancel (osascript exits non-zero with
 * error -128), a timeout (`giving up` returns empty text, exit 0; probed) or an
 * empty answer. The error object is never read: it is not needed, and nothing
 * about this dialog belongs in a message.
 *
 * Exactly ONE trailing newline (osascript's) is removed, never `trim()`: the
 * value is the user's secret, and whitespace in it is the caller's to refuse,
 * not this function's to edit.
 */
export async function promptForPassword(
  origin: string,
  username: string,
  name: string,
  run: DialogRunner = realRunner,
): Promise<string | null> {
  let out: string;
  try {
    out = await run(buildSavePasswordDialogScript(origin, username, name), requestSignal());
  } catch {
    return null;
  }
  const pw = typeof out === "string" ? out.replace(/\r?\n$/, "") : "";
  return pw.length > 0 ? pw : null;
}

export async function confirmInjection(
  boundOrigin: string,
  username: string,
  requestedDomain?: string,
  run: DialogRunner = realRunner,
): Promise<ConsentOutcome> {
  return ask(buildDialogScript(boundOrigin, username, requestedDomain), run);
}

export async function confirmSecretInjection(
  boundOrigin: string,
  secretName: string,
  run: DialogRunner = realRunner,
): Promise<ConsentOutcome> {
  return ask(buildSecretDialogScript(boundOrigin, secretName), run);
}
