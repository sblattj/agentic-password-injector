import { spawn, spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { KiroLogin } from "./config.ts";

// Everything that talks to kiro-cli. Each call runs the CLI with HOME set on the
// CHILD only, from a neutral cwd (a repo cwd loads workspace agents and costs
// more), and bounded in time.

const ANSI = /\x1b\[[0-9;?]*[A-Za-z]/g;
export const stripAnsi = (s: string) => s.replace(ANSI, "");

export interface WhoAmI { loggedIn: boolean; method?: string; email?: string; profile?: string }

export function parseWhoami(out: string): WhoAmI {
  const s = stripAnsi(out);
  if (/not logged in/i.test(s)) return { loggedIn: false };
  const m = s.match(/Logged in with ([^\n(]+)/i);
  if (!m) return { loggedIn: false };
  const email = s.match(/Email:\s*(\S+)/i)?.[1];
  const profile = s.match(/Profile:\s*\n\s*(\S+)/i)?.[1];
  return { loggedIn: true, method: m[1]!.trim(), email, profile };
}

export interface Usage { plan?: string; used: number; limit: number; left: number; resets?: string }

/** Parses `/usage`: "Estimated Usage | resets on 2026-12-01 | KIRO POWER" + "Credits (7752.82 of 10000 covered in plan)". */
export function parseUsage(out: string): Usage | null {
  const s = stripAnsi(out).replace(/,(?=\d{3})/g, "");
  const c = s.match(/Credits\s*\(\s*([\d.]+)\s+of\s+([\d.]+)/i);
  if (!c) return null;
  const used = Number(c[1]), limit = Number(c[2]);
  if (!Number.isFinite(used) || !Number.isFinite(limit)) return null;
  const head = s.match(/Estimated Usage\s*\|\s*resets on\s*([0-9-]+)\s*\|\s*([^\n]+)/i);
  return { used, limit, left: Math.round((limit - used) * 100) / 100, resets: head?.[1], plan: head?.[2]?.trim() };
}

export interface DeviceFlow { url: string; code?: string }

export function parseDeviceFlow(out: string): DeviceFlow | null {
  const s = stripAnsi(out);
  const url = s.match(/https:\/\/\S+?user_code=[A-Z0-9-]+/)?.[0];
  if (!url) return null;
  return { url, code: s.match(/Code:\s*([A-Z0-9-]+)/)?.[1] };
}

export type Runner = (home: string, args: string[], timeoutS: number) => { status: number | null; out: string };

export const realRunner: Runner = (home, args, timeoutS) => {
  const bin = process.env.APINJ_KIRO_CLI || "kiro-cli";
  // macOS has no `timeout`; perl's alarm bounds the child.
  const r = spawnSync("perl", ["-e", `alarm ${timeoutS}; exec @ARGV`, bin, ...args], {
    cwd: tmpdir(), env: { ...process.env, HOME: home }, encoding: "utf8", maxBuffer: 4 << 20,
  });
  return { status: r.status, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
};

export function whoami(home: string, run: Runner = realRunner): WhoAmI {
  return parseWhoami(run(home, ["whoami"], 30).out);
}

/** `--v2`: the v3 engine sends `/usage` to the model as text instead of answering it. */
export function usage(home: string, run: Runner = realRunner): Usage | null {
  return parseUsage(run(home, ["chat", "--v2", "--no-interactive", "/usage"], 90).out);
}

export function loginArgs(l: KiroLogin): string[] {
  const a = ["login", "--license", l.license, "--use-device-flow"];
  if (l.license === "pro") {
    if (!l.startUrl || !l.region) throw new Error("login.startUrl and login.region are required for license pro");
    a.push("--identity-provider", l.startUrl, "--region", l.region);
  }
  return a;
}

export interface LoginProc { flow: Promise<DeviceFlow>; done: Promise<number | null>; kill: () => void; log: () => string }

/** Starts the device-flow login under `home` and resolves the URL as soon as kiro-cli prints it. */
export function startDeviceLogin(home: string, l: KiroLogin, timeoutS: number): LoginProc {
  const bin = process.env.APINJ_KIRO_CLI || "kiro-cli";
  const child = spawn("perl", ["-e", `alarm ${timeoutS}; exec @ARGV`, bin, ...loginArgs(l)], {
    cwd: tmpdir(), env: { ...process.env, HOME: home }, stdio: ["ignore", "pipe", "pipe"],
  });
  let buf = "";
  let found: ((f: DeviceFlow) => void) | null = null;
  let lost: ((e: Error) => void) | null = null;
  const flow = new Promise<DeviceFlow>((ok, err) => { found = ok; lost = err; });
  const onData = (b: Buffer) => {
    buf += b.toString();
    if (buf.length > 1 << 20) buf = buf.slice(-(1 << 19));
    const f = parseDeviceFlow(buf);
    if (f && found) { found(f); found = null; }
  };
  child.stdout.on("data", onData);
  child.stderr.on("data", onData);
  const done = new Promise<number | null>((ok) => child.on("exit", (code) => {
    if (found && lost) lost(new Error("kiro-cli login exited before printing a device URL"));
    ok(code);
  }));
  return { flow, done, kill: () => child.kill("SIGTERM"), log: () => stripAnsi(buf).replace(/[▰▱]+ Logging in\.\.\./g, "") };
}

export const dataDir = (home: string) => join(home, "Library", "Application Support", "kiro-cli");
