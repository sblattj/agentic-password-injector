import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";

// One browser per account, with its own user-data-dir, so the account's IdP
// session (cookies, "stay signed in") never mixes with the browser you use every
// day. Your daily browser is very likely signed in as a DIFFERENT identity at
// the same IdP, and approving a device code there would log this account's HOME
// in as that other identity.
//
// The DevTools port is chosen by the browser (`--remote-debugging-port=0`) and
// read back from DevToolsActivePort, so it can never land on a port some other
// app (a chat client, your daily browser) already listens on.

export const DEFAULT_BROWSER = "/Applications/Vivaldi.app/Contents/MacOS/Vivaldi";

export interface AccountBrowser { base: string; proc: ChildProcess; stop: () => void }

export function browserBinary(env: Record<string, string | undefined> = process.env): string {
  return env.APINJ_ACCOUNTS_BROWSER || DEFAULT_BROWSER;
}

async function probe(base: string): Promise<boolean> {
  try {
    const r = await fetch(`${base}/json/version`, { signal: AbortSignal.timeout(1500) });
    return r.ok;
  } catch { return false; }
}

export async function launchAccountBrowser(profile: string, opts: { headed?: boolean; timeoutMs?: number } = {}): Promise<AccountBrowser> {
  mkdirSync(profile, { recursive: true, mode: 0o700 });
  const portFile = join(profile, "DevToolsActivePort");
  rmSync(portFile, { force: true });
  const args = [
    `--user-data-dir=${profile}`, "--remote-debugging-port=0", "--remote-debugging-address=127.0.0.1",
    "--no-first-run", "--no-default-browser-check", "about:blank",
  ];
  if (!opts.headed) args.unshift("--headless=new");
  const proc = spawn(browserBinary(), args, { stdio: "ignore", detached: false });
  const stop = () => { try { proc.kill("SIGTERM"); } catch { /* gone */ } };
  const deadline = Date.now() + (opts.timeoutMs ?? 20_000);
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) break;
    if (existsSync(portFile)) {
      const port = Number(readFileSync(portFile, "utf8").split("\n")[0]);
      if (port > 0) {
        for (const host of ["127.0.0.1", "[::1]"]) {
          const base = `http://${host}:${port}`;
          if (await probe(base)) return { base, proc, stop };
        }
      }
    }
    await Bun.sleep(250);
  }
  stop();
  throw new Error("account browser did not start (no DevToolsActivePort)");
}

export async function openTab(base: string, url: string): Promise<string> {
  const r = await fetch(`${base}/json/new?${url}`, { method: "PUT" });
  if (!r.ok) throw new Error(`could not open a tab (${r.status})`);
  return ((await r.json()) as { id: string }).id;
}

/**
 * Wait until the new tab has left its first navigation: a CDP attach while the
 * initial load is still in flight wedges the page (every Runtime.evaluate then
 * times out, seen on a headless Vivaldi). Read from /json/list only, no attach.
 * Waits for a titled https page, then settles a moment; gives up quietly at the bound.
 */
export async function waitForFirstLoad(base: string, id: string, timeoutMs = 20_000, settleMs = 1500): Promise<void> {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const list = (await fetch(`${base}/json/list`).then((r) => r.json()).catch(() => [])) as { id: string; url: string; title: string }[];
    const t = list.find((x) => x.id === id);
    if (t && t.url.startsWith("https://") && t.title && t.title !== t.url) break;
    await Bun.sleep(250);
  }
  await Bun.sleep(settleMs);
}
