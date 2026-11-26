#!/usr/bin/env bun
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  ACCOUNT_NAME_RE, ConfigError, configPath, dataRoot, homeOf, load, pick, save, toggleTarget,
  type Account, type Registry,
} from "./config.ts";
import { dataDir, usage, whoami, type Usage } from "./kiro.ts";
import { homeConflict, loginAccount } from "./login.ts";
import { keychainLookup } from "../vault/keychain.ts";

// apinj-accounts: several logins for one CLI tool (Kiro first), each in its own
// HOME, so one account can run without logging the other out. Modeled on
// macsub's verbs. Credentials stay in the macOS Keychain under apinj:<entry>;
// this tool only ever reads their attributes, and every keystroke that carries
// one goes through the injector's gated fill.

const USAGE = `apinj-accounts: several Kiro logins side by side, one HOME each

  add <name> [--home DIR] [--pinned] [--from ACCOUNT] [--license pro|free]
             [--start-url URL] [--region R] [--credential ENTRY] [--signin-origin ORIGIN]
                                register an account (a new HOME under the data dir by default)
  ls [--json]                   every account: login state, identity, credential entry
  usage [name] [--json]         credits used / left per account, and the best pick
  swap [name] | --best          set the active account (two accounts: bare swap toggles)
  best                          swap to the account with the most credits left
  current                       the active account
  home [name]                   print the account's HOME   (name defaults to $APINJ_ACCOUNT, then active)
  data-dir [name]               print the account's kiro-cli data dir (auth + sessions db)
  run [name] -- CMD ARGS...     run CMD with HOME set to the account's HOME
  whoami [name]                 kiro-cli whoami under that HOME
  login <name> [--headed] [--timeout S]
                                device-flow login in the account's own browser, filled by the injector
  shim <dir>                    write <dir>/kiro-cli that picks the account at exec time
  rm <name>                     unregister (the HOME is left on disk)

Registry: ${"$"}APINJ_ACCOUNTS_CONFIG or ~/.config/apinj-accounts/accounts.json (no secrets in it).
`;

function flag(args: string[], f: string): boolean {
  const i = args.indexOf(f);
  if (i < 0) return false;
  args.splice(i, 1);
  return true;
}

function opt(args: string[], f: string): string | undefined {
  const i = args.indexOf(f);
  if (i < 0) return undefined;
  const v = args[i + 1];
  if (v === undefined || v.startsWith("--")) throw new ConfigError(`${f} needs a value`);
  args.splice(i, 2);
  return v;
}

const out = (s: string) => process.stdout.write(s + "\n");
const err = (s: string) => process.stderr.write(s + "\n");

function fmtUsage(u: Usage | null): string {
  return u ? `${u.left.toFixed(2)} left of ${u.limit} (${u.used.toFixed(2)} used${u.plan ? `, ${u.plan}` : ""}${u.resets ? `, resets ${u.resets}` : ""})` : "credits unreadable";
}

export function bestOf(rows: { name: string; usage: Usage | null; loggedIn: boolean }[]): string | null {
  const ok = rows.filter((r) => r.loggedIn && r.usage);
  ok.sort((a, b) => b.usage!.left - a.usage!.left);
  return ok[0]?.name ?? null;
}

function usageRows(r: Registry, names: string[]) {
  return names.map((name) => {
    const home = homeOf(r.accounts[name]!);
    const w = whoami(home);
    return { name, home, loggedIn: w.loggedIn, email: w.email, usage: w.loggedIn ? usage(home) : null };
  });
}

async function main(argv: string[]): Promise<number> {
  const args = [...argv];
  const cmd = args.shift();
  const cfg = configPath();
  if (!cmd || cmd === "-h" || cmd === "--help" || cmd === "help") { out(USAGE); return 0; }

  if (cmd === "run") {
    const dd = args.indexOf("--");
    if (dd < 0 || dd === args.length - 1) throw new ConfigError("usage: run [name] -- CMD ARGS...");
    const r = load(cfg);
    const [, a] = pick(r, dd > 0 ? args[0] : undefined);
    const res = spawnSync(args[dd + 1]!, args.slice(dd + 2), { stdio: "inherit", env: { ...process.env, HOME: homeOf(a) } });
    return res.status ?? 1;
  }

  const json = flag(args, "--json");
  const r = load(cfg);

  switch (cmd) {
    case "add": {
      const name = args.shift();
      if (!name || !ACCOUNT_NAME_RE.test(name)) throw new ConfigError(`add: name must match ${ACCOUNT_NAME_RE}`);
      if (r.accounts[name]) throw new ConfigError(`account '${name}' already exists (rm it first)`);
      const pinned = flag(args, "--pinned");
      const from = opt(args, "--from");
      const base = from ? r.accounts[from] : undefined;
      if (from && !base) throw new ConfigError(`--from: unknown account '${from}'`);
      const dir = join(dataRoot(), "kiro", name);
      const home = opt(args, "--home") ?? join(dir, "home");
      const login = {
        license: (opt(args, "--license") ?? base?.login?.license ?? "pro") as "pro" | "free",
        startUrl: opt(args, "--start-url") ?? base?.login?.startUrl,
        region: opt(args, "--region") ?? base?.login?.region,
        credential: opt(args, "--credential") ?? `kiro-${name}`,
        signinOrigin: opt(args, "--signin-origin") ?? base?.login?.signinOrigin,
      };
      const a: Account = { tool: "kiro", home, login, ...(pinned ? { pinned: true } : { browserProfile: join(dir, "browser") }) };
      const next: Registry = { ...r, accounts: { ...r.accounts, [name]: a }, active: r.active ?? name };
      const c = homeConflict(next, name);
      if (c) throw new ConfigError(`add: ${c}`);
      if (!pinned) mkdirSync(homeOf(a), { recursive: true, mode: 0o700 });
      save(next, cfg);
      out(`added ${name}${pinned ? " (pinned)" : ""}: HOME=${homeOf(a)}`);
      return 0;
    }
    case "ls": {
      const rows = await Promise.all(Object.entries(r.accounts).map(async ([name, a]) => {
        const home = homeOf(a);
        const w = whoami(home);
        const entry = a.login?.credential;
        const cred = entry ? await keychainLookup(entry).catch(() => null) : null;
        return { name, active: r.active === name, pinned: !!a.pinned, home, loggedIn: w.loggedIn, email: w.email ?? null,
          credential: entry ?? null, credentialSaved: !!cred };
      }));
      if (json) { out(JSON.stringify(rows, null, 2)); return 0; }
      for (const x of rows)
        out(`${x.active ? "*" : " "} ${x.name.padEnd(12)} ${x.loggedIn ? `logged in as ${x.email ?? "?"}` : "not logged in"}` +
          `${x.pinned ? "  [pinned]" : ""}  cred ${x.credential ?? "-"}${x.credentialSaved ? "" : " (not saved)"}  HOME=${x.home}`);
      if (!rows.length) out("no accounts (apinj-accounts add <name>)");
      return 0;
    }
    case "usage": {
      const names = args[0] ? [pick(r, args[0])[0]] : Object.keys(r.accounts);
      const rows = usageRows(r, names);
      const best = bestOf(rows);
      if (json) { out(JSON.stringify({ accounts: rows, best }, null, 2)); return 0; }
      for (const x of rows) out(`${x.name.padEnd(12)} ${x.loggedIn ? fmtUsage(x.usage) : "not logged in"}`);
      if (best) out(`best: ${best}`);
      return 0;
    }
    case "swap": case "use": case "best": {
      let target: string;
      if (cmd === "best" || flag(args, "--best")) {
        const best = bestOf(usageRows(r, Object.keys(r.accounts)));
        if (!best) throw new ConfigError("no logged-in account with readable credits");
        target = best;
      } else target = args[0] ? pick(r, args[0])[0] : toggleTarget(r);
      save({ ...r, active: target }, cfg);
      out(`active: ${target}  HOME=${homeOf(r.accounts[target]!)}`);
      return 0;
    }
    case "current": out(r.active ?? "(none)"); return 0;
    case "home": out(homeOf(pick(r, args[0])[1])); return 0;
    case "data-dir": out(dataDir(homeOf(pick(r, args[0])[1]))); return 0;
    case "whoami": {
      const [n, a] = pick(r, args[0]);
      const w = whoami(homeOf(a));
      out(json ? JSON.stringify({ name: n, ...w }) : `${n}: ${w.loggedIn ? `logged in (${w.method}) as ${w.email ?? "?"}` : "not logged in"}`);
      return w.loggedIn ? 0 : 1;
    }
    case "login": {
      const name = args.shift();
      if (!name) throw new ConfigError("login <name>");
      pick(r, name);
      const headed = flag(args, "--headed");
      const t = opt(args, "--timeout");
      const res = await loginAccount(r, name, { headed, timeoutS: t ? Number(t) : undefined, log: (s) => err(`[${name}] ${s}`) });
      if (res.ok) { out(`${name}: ${res.already ? "already logged in" : "logged in"} as ${res.email ?? "?"}`); return 0; }
      err(`${name}: login failed: ${res.reason}${res.origin ? ` (on ${res.origin})` : ""}`);
      return 1;
    }
    case "shim": {
      const dir = args[0];
      if (!dir) throw new ConfigError("shim <dir>");
      mkdirSync(dir, { recursive: true });
      const self = resolve(import.meta.dir, "cli.ts");
      const real = spawnSync("sh", ["-c", "command -v kiro-cli"], { encoding: "utf8" }).stdout.trim();
      if (!real) throw new ConfigError("kiro-cli is not on PATH");
      const p = join(dir, "kiro-cli");
      writeFileSync(p, `#!/bin/sh\n# apinj-accounts shim: HOME is the account named by $APINJ_ACCOUNT, else the active one.\n` +
        `H=$(bun "${self}" home) || exit 1\nHOME="$H" exec "${real}" "$@"\n`);
      chmodSync(p, 0o755);
      out(p);
      return 0;
    }
    case "rm": {
      const [n] = pick(r, args[0]);
      const accounts = { ...r.accounts };
      delete accounts[n];
      const active = r.active === n ? Object.keys(accounts)[0] : r.active;
      save({ version: 1, accounts, ...(active ? { active } : {}) }, cfg);
      out(`removed ${n} (HOME left on disk)`);
      return 0;
    }
    default:
      err(`unknown command '${cmd}'\n`);
      out(USAGE);
      return 2;
  }
}

if (import.meta.main) {
  main(process.argv.slice(2)).then((c) => process.exit(c), (e) => {
    err(e instanceof ConfigError ? `apinj-accounts: ${e.message}` : `apinj-accounts: ${(e as Error)?.message ?? e}`);
    process.exit(e instanceof ConfigError ? 2 : 1);
  });
}

export { main };
