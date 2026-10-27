export class CdpError extends Error { constructor(public code: string, msg?: string) { super(msg ? `${code}: ${msg}` : code); } }
// 9222 is the ecosystem-default Chromium remote-debugging port. A browser started
// on a different port (e.g. Vivaldi on 9333) is pointed at via the CDP_BASE env var.
const BASE = process.env.CDP_BASE ?? "http://127.0.0.1:9222";
const TIMEOUT = Number(process.env.CDP_TIMEOUT_MS ?? 15000);
interface RawTarget { id: string; type: string; url: string; webSocketDebuggerUrl?: string; }

export function parseTargets(list: RawTarget[], tabId: string): { wsUrl: string; url: string } {
  const t = list.find((x) => x.id === tabId && x.webSocketDebuggerUrl);
  if (!t) throw new CdpError("tab_unavailable", `no target with id ${tabId}`);
  return { wsUrl: t.webSocketDebuggerUrl!, url: t.url };
}
export async function resolveTarget(tabId: string) {
  const res = await fetch(`${BASE}/json/list`);
  return parseTargets((await res.json()) as RawTarget[], tabId);
}
export type Send = <T = any>(method: string, params?: Record<string, unknown>) => Promise<T>;

export interface Dispatcher { send: Send; handle: (raw: string) => void; pendingCount: () => number }

/**
 * Request/response multiplexing over one CDP socket, split out from `withConn` so
 * the timer discipline is testable without a live browser.
 *
 * SECURITY (M2): the per-command timeout MUST be cleared the moment the command
 * settles. An uncleared timer keeps its closure — and therefore the `params`
 * object, which for `Input.insertText` holds the PLAINTEXT password — reachable
 * for CDP_TIMEOUT_MS (15s by default) after the caller has already run
 * `secret = ""`. Clearing on both the resolve and the reject path bounds the
 * plaintext's lifetime to the round-trip.
 */
export function createDispatcher(write: (frame: string) => void, timeoutMs: number = TIMEOUT): Dispatcher {
  let id = 0;
  const pending = new Map<number, { ok: (v: any) => void; err: (e: any) => void; timer: ReturnType<typeof setTimeout> }>();

  const settle = (n: number) => {
    const p = pending.get(n);
    if (!p) return null;
    pending.delete(n);
    clearTimeout(p.timer);
    return p;
  };

  const send: Send = (method, params = {}) => new Promise((ok, err) => {
    const myId = ++id;
    const timer = setTimeout(() => {
      if (settle(myId)) err(new CdpError("cdp_timeout", `${method} timed out`));
    }, timeoutMs);
    pending.set(myId, { ok, err, timer });
    write(JSON.stringify({ id: myId, method, params }));
  });

  const handle = (raw: string) => {
    let m: any;
    try { m = JSON.parse(raw); } catch { return; }
    if (!m?.id) return;
    const p = settle(m.id);
    if (!p) return;
    m.error ? p.err(new CdpError("cdp_error", m.error.message)) : p.ok(m.result);
  };

  return { send, handle, pendingCount: () => pending.size };
}

export async function withConn<T>(wsUrl: string, fn: (send: Send) => Promise<T>): Promise<T> {
  const ws = new WebSocket(wsUrl);
  await new Promise<void>((ok, err) => { ws.onopen = () => ok(); ws.onerror = () => err(new CdpError("tab_unavailable", "ws open failed")); });
  const { send, handle } = createDispatcher((frame) => ws.send(frame));
  ws.onmessage = (ev) => handle(ev.data as string);
  try { return await fn(send); } finally { ws.close(); }
}
export async function getOrigin(send: Send): Promise<string> {
  const r = await send<{ result: { value?: string } }>("Runtime.evaluate", { expression: "document.location.origin", returnByValue: true });
  return r.result.value ?? "";
}

/**
 * The main frame's `loaderId` — a browser-side identity for the CURRENT document
 * load, read from the Page domain rather than from page-world JS.
 *
 * This is the anti-TOCTOU token (C1): a same-origin string can survive a
 * navigation, and an in-flight cross-origin navigation can land between an origin
 * re-read and the keystroke, but ANY top-level document commit mints a new
 * loaderId. Comparing it before every keystroke is what makes "the tab is still
 * the page the human authorised" a checkable claim.
 *
 * Returns "" if the browser does not answer with one; callers MUST treat an empty
 * value as unverifiable and refuse, never as "unchanged".
 */
export async function getLoaderId(send: Send): Promise<string> {
  const r = await send<{ frameTree?: { frame?: { loaderId?: string } } }>("Page.getFrameTree");
  return r?.frameTree?.frame?.loaderId ?? "";
}
