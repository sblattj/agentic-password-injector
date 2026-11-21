import type { CdpError, Send } from "./cdp.ts";
import { ENDPOINT_REASONS } from "./endpoints.ts";
import { decideGate } from "./gate.ts";
import { originMatches } from "./origin.ts";

// The origin gate shared by every injecting tool. Split out of tools.ts so the
// passkey and one-time-code tools get these guarantees verbatim, without an
// import cycle through the tool registry.

/** What `gatedOnOrigin` needs: the tab, the socket, and the two live identities. */
export interface GateDeps {
  resolveTarget: (tabId: string) => Promise<{ wsUrl: string; url: string }>;
  withConn: <T>(wsUrl: string, fn: (send: Send) => Promise<T>) => Promise<T>;
  getOrigin: (send: Send) => Promise<string>;
  getLoaderId: (send: Send) => Promise<string>;
}

export type FillResult = { filled: boolean; submitted?: boolean; reason?: string };

export const fail = (reason: string): FillResult => ({ filled: false, reason });

/**
 * Thrown by `guard` to abort a fill from deep inside `run` without typing.
 * Carries a fixed reason code, never a message that could echo page state.
 */
export class GateAbort extends Error {
  constructor(public reason: string) { super(reason); }
}

/**
 * A pre-keystroke check: resolves if the tab is still what was authorised, else
 * throws. Passed down into `typeIntoField` so the LAST thing before the keystroke
 * is another assertion, not a stale one from three round-trips ago (M3).
 */
export type Guard = () => Promise<void>;

// Reason codes raised as exceptions from inside `run` that must survive the outer
// catch verbatim instead of collapsing to `tab_unavailable` — the user needs to
// see WHY nothing was typed.
export const PASSTHROUGH_REASONS = new Set(["focus_lost", "navigated_during_consent"]);

/**
 * Everything after "which secret" is settled: connect, origin-check, consent,
 * gate, and hand `run` a guard that re-asserts before every keystroke.
 *
 * Split out of `gated` so a NAMED SECRET gets these guarantees verbatim rather
 * than in a second, subtly-different copy. What differs between a credential and
 * a secret is entirely upstream of here — which vault answers, what the dialog
 * says, which field is legal — and none of that belongs in the TOCTOU path.
 */
export async function gatedOnOrigin(
  d: GateDeps,
  tabId: string,
  savedOrigin: string,
  consent: () => Promise<boolean>,
  run: (send: Send, guard: Guard) => Promise<FillResult>,
): Promise<FillResult> {
  let target: { wsUrl: string };
  try { target = await d.resolveTarget(tabId); } catch (e) {
    // An endpoint refusal says WHY (wrong name, read-only browser, bad config);
    // everything else, including a fetch failure, is still `tab_unavailable`.
    const code = (e as { code?: string })?.code;
    return fail(code && ENDPOINT_REASONS.has(code) ? code : "tab_unavailable");
  }

  try {
    return await d.withConn(target.wsUrl, async (send) => {
      let tabOrigin: string;
      let loaderId: string;
      try {
        tabOrigin = await d.getOrigin(send);
        loaderId = await d.getLoaderId(send);
      } catch { return fail("tab_unavailable"); }

      // Pre-consent short-circuit: never prompt about a tab we would refuse anyway.
      if (!originMatches(tabOrigin, savedOrigin)) return fail("origin_mismatch");
      // Fail closed: with no loaderId there is no way to prove the document did
      // not change under the dialog, so the fill is unverifiable, not "fine".
      if (!loaderId) return fail("tab_unavailable");

      /**
       * Called immediately before EVERY keystroke. Both facts must still hold:
       * the live origin still matches what the human authorised, AND the document
       * is the same load it was when they authorised it.
       */
      const guard: Guard = async () => {
        let liveOrigin: string;
        let liveLoader: string;
        try {
          liveOrigin = await d.getOrigin(send);
          liveLoader = await d.getLoaderId(send);
        } catch { throw new GateAbort("tab_unavailable"); }
        if (liveOrigin !== tabOrigin || !originMatches(liveOrigin, savedOrigin)) {
          throw new GateAbort("navigated_during_consent");
        }
        if (!liveLoader || liveLoader !== loaderId) {
          throw new GateAbort("navigated_during_consent");
        }
      };

      const allow = await consent();
      const g = decideGate({ tabOrigin, savedOrigin, allow });
      if (!g.ok) return fail(g.reason);

      // The dialog just blocked for up to a minute. Nothing below may assume the
      // tab is still the tab, hence the post-consent re-check and the per-keystroke
      // ones inside `run`.
      try { await guard(); } catch (e) { return fail((e as GateAbort).reason); }

      return await run(send, guard);
    });
  } catch (e) {
    // Nothing past the gate should throw, but a socket death mid-flight must not
    // surface a raw message — collapse to a fixed reason.
    if (e instanceof GateAbort) return fail(e.reason);
    const code = (e as CdpError)?.code;
    if (code === "vault_locked" || code === "decrypt_failed" || PASSTHROUGH_REASONS.has(code)) return fail(code);
    return fail("tab_unavailable");
  }
}

