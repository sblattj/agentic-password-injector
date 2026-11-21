import { getLoaderId, getOrigin, resolveTarget, withConn, type CdpError, type Send } from "./cdp.ts";
import { confirmKind, dialogRequired, type PromptKind } from "./consent.ts";
import { fail, gatedOnOrigin, type FillResult, type GateDeps, type Guard } from "./gated.ts";
import { tabRefReason } from "./endpoints.ts";
import { normalizeSaveOrigin, isValidSecretName } from "./validate.ts";
import { passkeyLookup, passkeyStore, type PasskeyEntry, type PasskeyRecord } from "./vault/passkey.ts";

// ── Agent passkeys over the CDP WebAuthn domain ──────────────────────────────
//
// The agent gets its OWN passkey per site. It lives in a virtual authenticator
// that exists on ONE tab target for the duration of ONE tool call: created after
// the origin gate and consent, removed in `finally`. The human's platform
// authenticators (Touch ID, iCloud Keychain, security keys) are never touched,
// in this tab or any other.
//
// Why one call does the whole ceremony: the authenticator belongs to the CDP
// session that created it, and `withConn` closes that session when the tool
// returns. So the tool arms the authenticator, optionally clicks the page's
// trigger itself, waits (bounded) for the credential to appear or be used, and
// tears down. CDP events are not awaited (the dispatcher drops id-less frames);
// `WebAuthn.getCredentials` is polled instead.
//
// Chromium refuses a WebAuthn ceremony unless the tab is VISIBLE (the active tab
// of an unminimised window): `ChromeWebAuthenticationDelegate::IsFocused` checks
// `GetVisibility() == VISIBLE`, and focus emulation does not satisfy it. The tool
// never raises a window itself; a hidden tab is refused with `tab_not_visible`.

export interface PasskeyDeps extends GateDeps {
  lookup: (name: string) => PasskeyEntry | null;
  store: (name: string, origin: string, rec: PasskeyRecord, opts: { replace?: { rpId: string } }) => void;
  confirm: (kind: PromptKind, origin: string, name: string) => Promise<boolean>;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
}

export const REAL_PASSKEY_DEPS: PasskeyDeps = {
  resolveTarget, withConn, getOrigin, getLoaderId,
  lookup: (name) => passkeyLookup(name),
  store: (name, origin, rec, opts) => passkeyStore(name, origin, rec, opts),
  confirm: async (kind, origin, name) => !dialogRequired() || confirmKind(kind, origin, name),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  now: () => Date.now(),
};

/** Default and ceiling for a ceremony wait. Below the ~30 s many MCP gateways allow (issue #1). */
export const PASSKEY_WAIT_DEFAULT_MS = 20_000;
export const PASSKEY_WAIT_MAX_MS = 25_000;
const POLL_MS = 250;

export function clampWait(raw: unknown, def = PASSKEY_WAIT_DEFAULT_MS, max = PASSKEY_WAIT_MAX_MS): number {
  const n = typeof raw === "number" && Number.isFinite(raw) ? raw : def;
  return Math.min(max, Math.max(1000, Math.floor(n)));
}

export const AUTHENTICATOR_OPTIONS = {
  protocol: "ctap2",
  transport: "internal",
  hasResidentKey: true,
  hasUserVerification: true,
  isUserVerified: true,
  automaticPresenceSimulation: true,
} as const;

/** True when `rpId` is the host itself or a parent domain of it (WebAuthn's own rule, minus the PSL). */
export function rpIdFits(origin: string, rpId: string): boolean {
  let host: string;
  try { host = new URL(origin).hostname.toLowerCase(); } catch { return false; }
  const rp = rpId.toLowerCase();
  return !!rp && (host === rp || host.endsWith("." + rp));
}

class Refuse extends Error { constructor(public reason: string) { super(reason); } }

async function tabVisible(send: Send): Promise<boolean> {
  const r = await send<{ result: { value?: string } }>("Runtime.evaluate", { expression: "document.visibilityState", returnByValue: true });
  return r?.result?.value === "visible";
}

/** Clicks the trigger with a user gesture, since `create()`/`get()` may require transient activation. */
async function clickTrigger(send: Send, selector: string): Promise<boolean> {
  const r = await send<{ result: { value?: boolean } }>("Runtime.evaluate", {
    expression: `(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e)return false;e.click();return true})()`,
    returnByValue: true,
    userGesture: true,
  });
  return r?.result?.value === true;
}

/**
 * Arms a virtual authenticator on this session, runs `body`, and ALWAYS removes
 * it again. A teardown fault is swallowed: the session closing removes it anyway,
 * and a teardown error must not mask the real result.
 */
async function withAuthenticator<T>(send: Send, body: (authenticatorId: string) => Promise<T>): Promise<T> {
  await send("WebAuthn.enable", { enableUI: false });
  let id = "";
  try {
    const r = await send<{ authenticatorId: string }>("WebAuthn.addVirtualAuthenticator", { options: AUTHENTICATOR_OPTIONS });
    id = r?.authenticatorId ?? "";
    if (!id) throw new Refuse("tab_unavailable");
    return await body(id);
  } finally {
    if (id) { try { await send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: id }); } catch { /* see above */ } }
    try { await send("WebAuthn.disable", {}); } catch { /* see above */ }
  }
}

interface CdpCredential {
  credentialId: string; rpId?: string; privateKey: string; userHandle?: string; signCount: number;
  isResidentCredential?: boolean; backupEligibility?: boolean; backupState?: boolean;
}

async function credentials(send: Send, authenticatorId: string): Promise<CdpCredential[]> {
  const r = await send<{ credentials?: CdpCredential[] }>("WebAuthn.getCredentials", { authenticatorId });
  return Array.isArray(r?.credentials) ? r.credentials : [];
}

function toRecord(c: CdpCredential): PasskeyRecord {
  return {
    credentialId: c.credentialId,
    rpId: c.rpId ?? "",
    privateKey: c.privateKey,
    userHandle: c.userHandle ?? "",
    signCount: c.signCount,
    ...(typeof c.backupEligibility === "boolean" ? { backupEligibility: c.backupEligibility } : {}),
    ...(typeof c.backupState === "boolean" ? { backupState: c.backupState } : {}),
  };
}

const refuseOr = (e: unknown, fallback: string): string => {
  if (e instanceof Refuse) return e.reason;
  const code = (e as CdpError)?.code;
  return code === "vault_locked" || code === "vault_error" ? code : fallback;
};

async function trigger(send: Send, guard: Guard, selector: string | null) {
  if (!selector) return;
  await guard();
  if (!(await clickTrigger(send, selector))) throw new Refuse("no_trigger");
}

// ── passkey_register ─────────────────────────────────────────────────────────

export type RegisterResult =
  | { saved: true; name: string; origin: string; rpId: string }
  | { saved: false; reason: string };

export async function passkeyRegister(args: unknown, d: PasskeyDeps = REAL_PASSKEY_DEPS): Promise<RegisterResult> {
  const a = (args ?? {}) as { tabId?: unknown; name?: unknown; origin?: unknown; selector?: unknown; timeoutMs?: unknown; replace?: unknown };
  const no = (reason: string): RegisterResult => ({ saved: false, reason });
  const tabId = typeof a.tabId === "string" ? a.tabId : "";
  const tabRefused = tabRefReason(tabId);
  if (tabRefused) return no(tabRefused);
  const name = typeof a.name === "string" ? a.name : "";
  if (!isValidSecretName(name)) return no("invalid_name");
  const origin = normalizeSaveOrigin(a.origin);
  if (!origin) return no("invalid_origin");
  const selector = typeof a.selector === "string" && a.selector ? a.selector : null;
  const wait = clampWait(a.timeoutMs);

  let existing: PasskeyEntry | null;
  try { existing = d.lookup(name); } catch (e) { return no(refuseOr(e, "vault_error")); }
  if (existing && a.replace !== true) return no("exists");

  let saved: PasskeyRecord | null = null;
  const r: FillResult = await gatedOnOrigin(d, tabId, origin, () => d.confirm("passkey_register", origin, name), async (send, guard) => {
    try {
      if (!(await tabVisible(send))) return fail("tab_not_visible");
      return await withAuthenticator(send, async (authId) => {
        await trigger(send, guard, selector);
        const deadline = d.now() + wait;
        for (;;) {
          const c = (await credentials(send, authId)).find((x) => x.rpId && rpIdFits(origin, x.rpId));
          if (c) {
            const rec = toRecord(c);
            d.store(name, origin, rec, existing ? { replace: { rpId: existing.rpId } } : {});
            saved = rec;
            return { filled: true };
          }
          if (d.now() >= deadline) return fail("timeout");
          await d.sleep(Math.max(0, Math.min(POLL_MS, deadline - d.now())));
        }
      });
    } catch (e) {
      if (e instanceof Refuse) return fail(e.reason);
      const code = (e as CdpError)?.code;
      if (code === "vault_locked" || code === "vault_error") return fail(code);
      throw e; // let the gate map it (navigation aborts keep their reason)
    }
  });
  if (!r.filled || !saved) return no(r.reason ?? "tab_unavailable");
  const rpId = (saved as PasskeyRecord).rpId;
  saved = null;
  return { saved: true, name, origin, rpId };
}

// ── passkey_login ────────────────────────────────────────────────────────────

export type LoginResult = { used: boolean; reason?: string };

export async function passkeyLogin(args: unknown, d: PasskeyDeps = REAL_PASSKEY_DEPS): Promise<LoginResult> {
  const a = (args ?? {}) as { tabId?: unknown; name?: unknown; selector?: unknown; timeoutMs?: unknown };
  const no = (reason: string): LoginResult => ({ used: false, reason });
  const tabId = typeof a.tabId === "string" ? a.tabId : "";
  const tabRefused = tabRefReason(tabId);
  if (tabRefused) return no(tabRefused);
  const name = typeof a.name === "string" ? a.name : "";
  if (!name) return no("name_required");
  if (!isValidSecretName(name)) return no("bad_name");
  const selector = typeof a.selector === "string" && a.selector ? a.selector : null;
  const wait = clampWait(a.timeoutMs);

  let entry: PasskeyEntry | null;
  try { entry = d.lookup(name); } catch (e) { return no(refuseOr(e, "vault_error")); }
  if (!entry) return no("not_found");
  const origin = entry.origin;
  if (!origin) return no("no_origin_binding");
  const found = entry;

  let warning: string | undefined;
  const r = await gatedOnOrigin(d, tabId, origin, () => d.confirm("passkey_login", origin, name), async (send, guard) => {
    try {
      if (!(await tabVisible(send))) return fail("tab_not_visible");
      // The private key is decrypted only here: past the origin gate, past consent.
      let rec: PasskeyRecord | null = found.getRecord();
      if (!rpIdFits(origin, rec.rpId)) return fail("origin_mismatch");
      const { credentialId, rpId, signCount: before } = rec;
      return await withAuthenticator(send, async (authId) => {
        await guard();
        await send("WebAuthn.addCredential", {
          authenticatorId: authId,
          credential: {
            credentialId: rec!.credentialId, isResidentCredential: true, rpId: rec!.rpId,
            privateKey: rec!.privateKey, userHandle: rec!.userHandle || undefined, signCount: rec!.signCount,
            ...(rec!.backupEligibility === undefined ? {} : { backupEligibility: rec!.backupEligibility }),
            ...(rec!.backupState === undefined ? {} : { backupState: rec!.backupState }),
          },
        });
        const keep = { ...rec! };
        rec = null;
        await trigger(send, guard, selector);
        const deadline = d.now() + wait;
        for (;;) {
          const c = (await credentials(send, authId)).find((x) => x.credentialId === credentialId);
          if (c && c.signCount > before) {
            // Persist the counter: a relying party may reject a count that goes backwards.
            try { d.store(name, origin, { ...keep, rpId, signCount: c.signCount }, { replace: { rpId } }); }
            catch { warning = "sign_count_not_saved"; }
            return { filled: true };
          }
          if (d.now() >= deadline) return fail("timeout");
          await d.sleep(Math.max(0, Math.min(POLL_MS, deadline - d.now())));
        }
      });
    } catch (e) {
      if (e instanceof Refuse) return fail(e.reason);
      const code = (e as CdpError)?.code;
      if (code === "vault_locked" || code === "vault_error") return fail(code);
      throw e;
    }
  });
  if (!r.filled) return no(r.reason ?? "tab_unavailable");
  return warning ? { used: true, reason: warning } : { used: true };
}

// ── Manifest entries (registered by tools.ts) ────────────────────────────────

const SELECTOR_DESC =
  "Optional CSS selector the tool clicks (with a user gesture) to start the ceremony, e.g. the site's " +
  "'Create passkey' or 'Sign in with a passkey' button. Without it the page must start the ceremony " +
  "itself within the wait.";
const TIMEOUT_DESC = `Max wait for the ceremony in ms (default ${PASSKEY_WAIT_DEFAULT_MS}, capped at ${PASSKEY_WAIT_MAX_MS}).`;

export const PASSKEY_TOOLS = [
  {
    name: "passkey_register",
    description:
      "Create an AGENT-OWNED passkey on a site and save it to the macOS Keychain as apinj-passkey:<name>, bound " +
      "to <origin>. After an origin match and consent, a virtual WebAuthn authenticator is added to this tab only, " +
      "the optional selector is clicked, and the new credential is read and stored; the authenticator is then " +
      "removed. The tab must be visible (active tab of an unminimised window). The human's own passkeys are not " +
      "used or touched. Returns only {saved, name, origin, rpId} or {saved:false, reason}; never the private key.",
    inputSchema: {
      type: "object",
      properties: {
        tabId: { type: "string", description: "CDP target id of the tab. A bare id is the CDP_BASE browser; `endpoint:<name>/<targetId>` is a browser named in CDP_ENDPOINTS (read-only endpoints refuse)" },
        name: { type: "string", description: "Entry name ([a-z0-9][a-z0-9._-], max 64); stored as apinj-passkey:<name>" },
        origin: { type: "string", description: "The site's origin, e.g. https://example.com; must match the tab" },
        selector: { type: "string", description: SELECTOR_DESC },
        timeoutMs: { type: "number", description: TIMEOUT_DESC },
        replace: { type: "boolean", description: "Overwrite an existing apinj-passkey:<name> entry" },
      },
      required: ["tabId", "name", "origin"],
      additionalProperties: false,
    },
    fn: (args: unknown) => passkeyRegister(args),
  },
  {
    name: "passkey_login",
    description:
      "Sign in with a saved AGENT passkey (apinj-passkey:<name>). Behind the same origin gate and consent as the " +
      "password tools, the credential is loaded into a virtual authenticator on this tab only, the optional selector " +
      "is clicked, and the tool waits until the site has used it, then saves the new sign count and removes the " +
      "authenticator. The tab must be visible. Returns only {used, reason?}; never the private key.",
    inputSchema: {
      type: "object",
      properties: {
        tabId: { type: "string", description: "CDP target id of the tab. A bare id is the CDP_BASE browser; `endpoint:<name>/<targetId>` is a browser named in CDP_ENDPOINTS (read-only endpoints refuse)" },
        name: { type: "string", description: "Entry name the passkey was registered under" },
        selector: { type: "string", description: SELECTOR_DESC },
        timeoutMs: { type: "number", description: TIMEOUT_DESC },
      },
      required: ["tabId", "name"],
      additionalProperties: false,
    },
    fn: (args: unknown) => passkeyLogin(args),
  },
] as const;
