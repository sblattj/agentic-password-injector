// test/live-check.ts — NOT part of `bun test`.
//
// Every other suite drives the page-world expressions against a shim, and a shim
// cannot model shadow-DOM event propagation. That gap was not theoretical: the
// post-insert burst shipped with `bubbles:true` alone, which reaches NO listener
// outside the shadow root — so on exactly the pages the piercing work exists for,
// the burst silently did nothing while every unit test stayed green. Only this
// file caught it.
//
// Requires a Chromium-family browser with a CDP port open. No secret is involved:
// the value typed is a sentinel. It creates its own tab and closes it.
//
//   CDP_BASE=http://127.0.0.1:9333 bun run test/live-check.ts
//
// Live-browser verification of the page-world expressions. No secret involved:
// the "value" typed is a sentinel string. Creates its own tab and closes it.
import { PIERCE_FN, typeIntoField, inspectField } from "../src/inject.ts";
import { probeExpr, chooseSecretField, SECRET_ATTR, type FieldInfo } from "../src/tools.ts";
import { createDispatcher } from "../src/cdp.ts";

const BASE = process.env.CDP_BASE ?? "http://127.0.0.1:9222";
const PAGE = `file://${import.meta.dir}/fixtures/shadow.html`;
const SENTINEL = "SENTINEL-1234567890";

const results: [string, boolean, string][] = [];
const check = (name: string, pass: boolean, detail = "") => results.push([name, pass, detail]);

const t = await (await fetch(`${BASE}/json/new?${encodeURIComponent(PAGE)}`, { method: "PUT" })).json();
const targetId: string = t.id;
try {
  const ws = new WebSocket(t.webSocketDebuggerUrl);
  await new Promise<void>((ok, err) => { ws.onopen = () => ok(); ws.onerror = () => err(new Error("ws")); });
  const { send, handle } = createDispatcher((f) => ws.send(f));
  ws.onmessage = (ev) => handle(ev.data as string);
  const evalv = async (expr: string) => {
    const r: any = await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text + " " + JSON.stringify(r.exceptionDetails.exception?.description ?? ""));
    return r.result.value;
  };
  await send("Runtime.enable");
  await send("Page.enable");
  // Wait for the custom elements to upgrade.
  for (let i = 0; i < 40 && !(await evalv(`!!document.querySelector('atlas-outer')?.shadowRoot`)); i++) await Bun.sleep(100);

  // ── PIERCE ────────────────────────────────────────────────────────────────
  check("pierce: light DOM hit", await evalv(`${PIERCE_FN}('#light')?.id`) === "light");
  check("pierce: ONE root deep (#pw inside atlas-outer)", await evalv(`${PIERCE_FN}('#pw')?.id`) === "pw");
  check("pierce: TWO roots deep (#ssn inside atlas-inner inside atlas-outer)",
    await evalv(`${PIERCE_FN}('#ssn')?.id`) === "ssn");
  check("pierce: HOST descends to its inner input",
    await evalv(`${PIERCE_FN}('#inner')?.id`) === "ssn");
  check("pierce: genuine miss is null", await evalv(`${PIERCE_FN}('#nope')`) === null);
  check("pierce: CLOSED root is unreachable", await evalv(`${PIERCE_FN}('#unreachable')`) === null);
  check("pierce: invalid selector is null, not a throw", await evalv(`${PIERCE_FN}('!!!')`) === null);
  check("pierce: installs no global", await evalv(`typeof window.__pierce`) === "undefined");

  // ── inspectField ──────────────────────────────────────────────────────────
  const send2 = send as any;
  check("inspectField: shadow password box", JSON.stringify(await inspectField(send2, "#pw")) === '{"type":"password","visible":true}');
  check("inspectField: shadow text box", JSON.stringify(await inspectField(send2, "#ssn")) === '{"type":"text","visible":true}');
  check("inspectField: miss is null", (await inspectField(send2, "#nope")) === null);

  // ── deep probe ────────────────────────────────────────────────────────────
  const shallow: FieldInfo[] = await evalv(probeExpr(SECRET_ATTR, "shallow", { includePassword: true }));
  const deep: FieldInfo[] = await evalv(probeExpr(SECRET_ATTR, "deep", { deep: true, includePassword: true }));
  check("probe shallow: sees ONLY the light-DOM input", shallow.length === 1 && shallow[0].id === "light",
    JSON.stringify(shallow.map((f) => f.id)));
  check("probe deep: also sees both shadow inputs", deep.length === 3 && deep.map((f) => f.id).sort().join(",") === "light,pw,ssn",
    JSON.stringify(deep.map((f) => f.id)));
  check("probe deep: password-only chooser is unambiguous here",
    chooseSecretField(deep, { kindText: false }).sel === deep.find((f) => f.id === "pw")!.sel);
  check("probe deep: kindText sees 3 candidates and REFUSES",
    chooseSecretField(deep, { kindText: true }).ambiguous === true);
  const stampSel = deep.find((f) => f.id === "ssn")!.sel;
  check("probe deep: a shadow stamp is resolvable by PIERCE, not by querySelector",
    (await evalv(`${PIERCE_FN}(${JSON.stringify(stampSel)})?.id`)) === "ssn" &&
    (await evalv(`document.querySelector(${JSON.stringify(stampSel)})`)) === null);

  // ── typeIntoField end to end, into a two-deep shadow input ────────────────
  await typeIntoField(send2, "#ssn", SENTINEL);
  check("typeIntoField: value landed in the SHADOW input",
    (await evalv(`${PIERCE_FN}('#ssn').value`)) === SENTINEL);
  check("typeIntoField: CLEAR replaced 'stale-value' rather than appending",
    !(await evalv(`${PIERCE_FN}('#ssn').value`)).includes("stale"));
  check("typeIntoField: the light-DOM field was NOT touched",
    (await evalv(`document.querySelector('#light').value`)) === "prefilled-light");
  check("typeIntoField: deep focus check passed (it would have thrown focus_lost)", true);

  // ── the keyup gap, and the opt-in that closes it ──────────────────────────
  const keyupsAfterInsert = await evalv(`window.__keyups`);
  check("insertText fires NO keyboard events (the ID.me failure)", keyupsAfterInsert === 0,
    `keyups=${keyupsAfterInsert}`);
  await typeIntoField(send2, "#ssn", SENTINEL, undefined, { events: true });
  const k = await evalv(`window.__keyups`), c = await evalv(`window.__changes`);
  // keyup is composed, so it crosses BOTH shadow boundaries to the window
  // listener — this is the assertion that failed with bubbles alone.
  check("events:true fires a keyup that ESCAPES two shadow roots", k > 0, `keyups=${k}`);
  // change is NOT composed natively, so it correctly stops at the shadow root.
  check("events:true leaves change un-composed, as the UA does", c === 0, `changes=${c}`);
  const inRoot = await evalv(`(()=>{const r=document.querySelector('atlas-outer').shadowRoot
      .querySelector('atlas-inner').shadowRoot;let n=0;r.addEventListener('change',()=>n++);
      const e=${PIERCE_FN}('#ssn');e.dispatchEvent(new Event('change',{bubbles:true}));return n})()`);
  check("…and a listener INSIDE the shadow root does receive it", inRoot === 1, `n=${inRoot}`);
  check("events:true still leaves the correct value",
    (await evalv(`${PIERCE_FN}('#ssn').value`)) === SENTINEL);

  // ── focus_lost is still real ──────────────────────────────────────────────
  await evalv(`${PIERCE_FN}('#ssn').disabled = true`);
  let threw = "";
  try { await typeIntoField(send2, "#ssn", SENTINEL); } catch (e) { threw = String((e as Error).message); }
  check("a disabled target refuses with focus_lost", threw.includes("focus_lost"), threw);
  ws.close();
} finally {
  await fetch(`${BASE}/json/close/${targetId}`);
}

let bad = 0;
for (const [n, ok, d] of results) { if (!ok) bad++; console.log(`${ok ? "PASS" : "FAIL"}  ${n}${d ? "  [" + d + "]" : ""}`); }
console.log(`\n${results.length - bad}/${results.length} live checks passed`);
process.exit(bad ? 1 : 0);
