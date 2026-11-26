import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

// The account registry. It holds NO secrets: names, HOME paths, the login
// settings a tool needs (start URL, region, license) and the NAME of the
// Keychain entry that carries the password. It lives outside any repo, in
// ~/.config/apinj-accounts/accounts.json (0600), because the login settings are
// specific to whoever runs this and do not belong in a public tree.

export const ACCOUNT_NAME_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;

export interface KiroLogin {
  /** `pro` = IAM Identity Center, `free` = Builder ID. */
  license: "pro" | "free";
  startUrl?: string;
  region?: string;
  /** Keychain entry `apinj:<credential>` holding username + password for the IdP page. */
  credential?: string;
  /** The IdP's sign-in origin the credential is bound to, e.g. https://login.example.com. */
  signinOrigin?: string;
}

export interface Account {
  tool: "kiro";
  /** The HOME the tool runs under for this account. */
  home: string;
  /**
   * A pinned account is never logged out, never logged in by this tool, and its
   * HOME is never written to. Use it for the login you already rely on.
   */
  pinned?: boolean;
  /** Chromium user-data-dir for this account's own login browser (cookies stay per account). */
  browserProfile?: string;
  login?: KiroLogin;
  note?: string;
}

export interface Registry {
  version: 1;
  active?: string;
  accounts: Record<string, Account>;
}

export function configPath(env: Record<string, string | undefined> = process.env): string {
  return env.APINJ_ACCOUNTS_CONFIG || join(homedir(), ".config", "apinj-accounts", "accounts.json");
}

export function dataRoot(env: Record<string, string | undefined> = process.env): string {
  return env.APINJ_ACCOUNTS_DATA || join(homedir(), ".local", "share", "apinj-accounts");
}

export function expandHome(p: string): string {
  return p === "~" ? homedir() : p.startsWith("~/") ? join(homedir(), p.slice(2)) : p;
}

export class ConfigError extends Error {}

export function validate(raw: unknown): Registry {
  const r = raw as Registry;
  if (!r || typeof r !== "object" || r.version !== 1 || typeof r.accounts !== "object" || !r.accounts)
    throw new ConfigError("accounts.json: expected {version: 1, accounts: {...}}");
  for (const [name, a] of Object.entries(r.accounts)) {
    if (!ACCOUNT_NAME_RE.test(name)) throw new ConfigError(`account '${name}': name must match ${ACCOUNT_NAME_RE}`);
    if (a.tool !== "kiro") throw new ConfigError(`account '${name}': unsupported tool '${(a as any).tool}'`);
    if (typeof a.home !== "string" || !a.home) throw new ConfigError(`account '${name}': home is required`);
    if (a.login && a.login.license !== "pro" && a.login.license !== "free")
      throw new ConfigError(`account '${name}': login.license must be pro or free`);
  }
  if (r.active !== undefined && !r.accounts[r.active]) throw new ConfigError(`active account '${r.active}' is not registered`);
  return r;
}

export function load(path = configPath()): Registry {
  if (!existsSync(path)) return { version: 1, accounts: {} };
  let raw: unknown;
  try { raw = JSON.parse(readFileSync(path, "utf8")); }
  catch { throw new ConfigError(`${path}: not valid JSON`); }
  return validate(raw);
}

export function save(r: Registry, path = configPath()): void {
  validate(r);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(r, null, 2) + "\n", { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
}

export function homeOf(a: Account): string {
  return resolve(expandHome(a.home));
}

/**
 * Which account a command means. Order: the explicit name, then
 * `APINJ_ACCOUNT` (so a harness can pick per process without touching the
 * registry), then the registry's active pointer.
 */
export function pick(r: Registry, name?: string, env: Record<string, string | undefined> = process.env): [string, Account] {
  const n = name || env.APINJ_ACCOUNT || r.active;
  if (!n) throw new ConfigError("no account given and none active (run: apinj-accounts swap <name>)");
  const a = r.accounts[n];
  if (!a) throw new ConfigError(`unknown account '${n}' (known: ${Object.keys(r.accounts).join(", ") || "none"})`);
  return [n, a];
}

/** `swap` with no name: with exactly two accounts, the other one. */
export function toggleTarget(r: Registry): string {
  const names = Object.keys(r.accounts);
  if (names.length !== 2) throw new ConfigError(`bare swap needs exactly two accounts (have ${names.length}); name one`);
  return names[0] === r.active ? names[1]! : names[0]!;
}

/**
 * Point <home>/Library/Keychains at the real one. macOS finds the login keychain
 * through HOME, so without this any keychain call under the account's HOME (kiro-cli
 * or a tool it starts) pops a "Keychain Not Found ... Reset To Defaults" dialog, and
 * a reset would wipe the real login keychain. Kiro's own login tokens live in its
 * data dir, not the keychain, so accounts stay separate. Never touches a pinned HOME.
 */
export function linkKeychains(a: Account, realHome = homedir()): "linked" | "present" | "skipped" {
  const home = homeOf(a);
  if (a.pinned || resolve(home) === resolve(realHome)) return "skipped";
  const lib = join(home, "Library");
  const link = join(lib, "Keychains");
  if (existsSync(link) || lstatExists(link)) return "present";
  mkdirSync(lib, { recursive: true, mode: 0o700 });
  symlinkSync(join(realHome, "Library", "Keychains"), link);
  return "linked";
}

function lstatExists(p: string): boolean {
  try { lstatSync(p); return true; } catch { return false; }
}
