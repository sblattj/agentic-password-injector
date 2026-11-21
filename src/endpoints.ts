// Named CDP endpoints (issue #4): one server, several browsers.
//
// A LEAF MODULE: cdp.ts imports it, so it imports nothing from this package.
//
// The config mirrors cdp-toolkit's, so one env value drives both tools:
//   CDP_BASE        the endpoint named `default`, stored verbatim
//                   (default http://127.0.0.1:9222).
//   CDP_ENDPOINTS   "teams=http://127.0.0.1:9333?mode=read,helium=http://127.0.0.1:9555"
// cdp-toolkit's CDP_ENDPOINTS_FILE is NOT read here.
//
// A tab is named `endpoint:<name>/<targetId>`; a bare `<targetId>` is the
// default endpoint and is never looked up anywhere else. The model only ever
// picks a NAME: every URL comes from the environment, so a tool call cannot
// point this process at a browser the operator did not configure.
//
// `?mode=read` marks an endpoint this server must never type into. Every tool
// that takes a tabId injects, so a read-only endpoint refuses all of them.
//
// The env is re-read on every call (no caching): a fixed config is picked up
// without a restart, and a bad one fails closed every time.

export class EndpointError extends Error {
  constructor(public code: string, msg?: string) { super(msg ? `${code}: ${msg}` : code); }
}

export interface Endpoint { name: string; base: string; readOnly: boolean }

export const DEFAULT_CDP_BASE = "http://127.0.0.1:9222";
export const ENDPOINT_PREFIX = "endpoint:";
const NAME_RE = /^[A-Za-z0-9_]+$/;

type Env = Record<string, string | undefined>;

const configError = (msg: string) => new EndpointError("endpoint_config_error", msg);

function parseBase(raw: string, name: string): { base: string; readOnly: boolean } {
  let url: URL;
  try { url = new URL(raw); } catch { throw configError(`endpoint '${name}': '${raw}' is not a valid URL`); }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw configError(`endpoint '${name}': must be http:// or https://`);
  if (url.hash) throw configError(`endpoint '${name}': must not carry a #fragment`);
  let readOnly = false;
  for (const [key, value] of url.searchParams) {
    if (key !== "mode") throw configError(`endpoint '${name}': unknown query parameter '${key}' (only ?mode=read or ?mode=write)`);
    if (value !== "read" && value !== "write") throw configError(`endpoint '${name}': unknown mode '${value}'`);
    readOnly = value === "read";
  }
  return { base: `${url.protocol}//${url.host}${url.pathname.replace(/\/+$/, "")}`, readOnly };
}

const sameBase = (a: string, b: string) => a.replace(/\/+$/, "") === b.replace(/\/+$/, "");

/** Every configured endpoint by name; `default` is always present. Throws `endpoint_config_error`. */
export function loadEndpoints(env: Env = process.env): Map<string, Endpoint> {
  const out = new Map<string, Endpoint>();
  for (const part of (env.CDP_ENDPOINTS ?? "").split(",")) {
    const entry = part.trim();
    if (!entry) continue;
    const eq = entry.indexOf("=");
    if (eq <= 0) throw configError(`entry '${entry}' is not name=url`);
    const name = entry.slice(0, eq).trim();
    if (!NAME_RE.test(name)) throw configError(`endpoint name '${name}' is invalid (letters, digits and '_' only)`);
    if (out.has(name)) throw configError(`duplicate endpoint name '${name}'`);
    out.set(name, { name, ...parseBase(entry.slice(eq + 1).trim(), name) });
  }
  const cdpBase = env.CDP_BASE;
  const configured = out.get("default");
  if (cdpBase !== undefined) {
    if (configured && !sameBase(configured.base, cdpBase)) throw configError("CDP_BASE and the endpoint 'default' disagree");
    out.set("default", { name: "default", base: cdpBase, readOnly: configured?.readOnly ?? false });
  } else if (!configured) {
    out.set("default", { name: "default", base: DEFAULT_CDP_BASE, readOnly: false });
  }
  return out;
}

/**
 * Split a tabId into its endpoint and CDP target id, refusing anything this
 * server must not type into. Codes: `tab_unavailable` (no target id),
 * `unknown_endpoint`, `endpoint_read_only`, `endpoint_config_error`.
 */
export function resolveTabRef(tabId: string, env: Env = process.env): { endpoint: Endpoint; targetId: string } {
  const all = loadEndpoints(env);
  let name = "default";
  let targetId = tabId;
  if (tabId.startsWith(ENDPOINT_PREFIX)) {
    const body = tabId.slice(ENDPOINT_PREFIX.length);
    const slash = body.indexOf("/");
    name = slash < 0 ? body : body.slice(0, slash);
    targetId = slash < 0 ? "" : body.slice(slash + 1);
  }
  const endpoint = all.get(name);
  if (!endpoint) throw new EndpointError("unknown_endpoint", `'${name}' (known: ${[...all.keys()].join(", ")})`);
  if (endpoint.readOnly) throw new EndpointError("endpoint_read_only", `'${name}' is configured ?mode=read`);
  if (!targetId) throw new EndpointError("tab_unavailable", "no target id; use endpoint:<name>/<targetId>");
  return { endpoint, targetId };
}

/** Fixed reason codes that must reach the caller verbatim rather than collapse to `tab_unavailable`. */
export const ENDPOINT_REASONS = new Set(["unknown_endpoint", "endpoint_read_only", "endpoint_config_error"]);

/**
 * The pre-vault check every injecting tool runs on its tabId: null if usable,
 * else a fixed reason code. Runs BEFORE any vault read or consent dialog, so a
 * read-only or unknown endpoint never unlocks a secret it would then refuse.
 */
export function tabRefReason(tabId: string, env: Env = process.env): string | null {
  if (!tabId) return "tab_unavailable";
  try { resolveTabRef(tabId, env); return null; }
  catch (e) { return e instanceof EndpointError ? e.code : "tab_unavailable"; }
}
