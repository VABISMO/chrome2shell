#!/usr/bin/env node
/**
 * ax-run: direct-run + an ACTIVE accessibility client.
 *
 * CVE-2026-113279 / CVE-2026-113271 need the AX client side live: the
 * re-entrant traversal / dangling-attribute-reference window opens while the
 * AX tree is being computed and serialized to a client (kProcessDeferredUpdates
 * / name+description computation). A page alone with
 * --force-renderer-accessibility has the cache but no client pulling the tree.
 *
 * This driver keeps Accessibility.getFullAXTree() running over CDP in a loop
 * while the page churns the DOM, and inherits everything else from direct-run
 * (beacon collection, stderr crash watch, phase trail, --extra flags).
 *
 * Usage:
 *   node harness/ax-run.mjs cases/CVE-2026-113279/map-remove-ax.html \
 *     --browser builds/145.0.7632.67/chrome-linux64/chrome \
 *     --out findings/raw/CVE-2026-113279.ax.json --stderr ... --timeout 90000
 */
import { createServer } from "node:http";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { extname, join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function parseArgs(argv) {
  const out = { page: null, timeoutMs: 60000, extra: [] };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--browser") out.browser = argv[++i];
    else if (a === "--js-flags") out.jsFlags = argv[++i];
    else if (a === "--out") out.out = argv[++i];
    else if (a === "--stderr") out.stderrPath = argv[++i];
    else if (a === "--timeout") out.timeoutMs = Number(argv[++i]);
    else if (a === "--gpu") out.gpu = true;
    else if (a === "--ax-interval") out.axIntervalMs = Number(argv[++i]);
    else if (a === "--trace-cats") out.traceCats = argv[++i];
    else if (a === "--watch-names") out.watchNames = argv[++i];
    else if (a === "--extra") out.extra.push(argv[++i]);
    else if (!out.page) out.page = a;
  }
  return out;
}

const args = parseArgs(process.argv);
if (!args.page || !args.browser) {
  console.error("usage: ax-run.mjs <page> --browser <path> [--ax-interval ms] [...]");
  process.exit(2);
}
const axInterval = args.axIntervalMs ?? 120;

const INJECT = `<script>(function(){
window.addEventListener('error', function(ev){
  // resource errors (media/img load failures) reach capture listeners with no
  // message/filename — only real script errors count
  if(!ev.message && !ev.filename) return;
  try{ fetch('/collect?e='+encodeURIComponent('ERR:'+(ev.message||'')+'@'+(ev.filename||'')+':'+(ev.lineno||0))); }catch(_){}
}, true);
window.addEventListener('unhandledrejection', function(ev){
  try{ fetch('/collect?e='+encodeURIComponent('REJ:'+String(ev.reason).slice(0,150))); }catch(_){}
});
var iv=setInterval(function(){
  if(window.__LAB_RESULT){
    clearInterval(iv);
    try{
      var b=btoa(unescape(encodeURIComponent(JSON.stringify(window.__LAB_RESULT))));
      navigator.sendBeacon('/collect',b)||fetch('/collect',{method:'POST',body:b});
    }catch(e){fetch('/collect?e='+encodeURIComponent('PUB:'+String(e)));}
  }
},50);
var _BT=Number(new URLSearchParams(location.search).get('beacon_ms'))||120000;setTimeout(function(){clearInterval(iv);fetch('/collect?e=timeout');},_BT);
})();</script>`;

let resolveResult;
const resultPromise = new Promise((r) => { resolveResult = r; });
let serverResult = null;
let progress = [];
let chromeExited = null;
let axCalls = 0, axErrors = 0, axLastErr = null;
let traceChunks = [];   // CDP Tracing.dataCollected payloads
let traceStarted = false;
const traceDiag = { methods: {} };
let traceCtl = null;   // {send} — set by axLoop so main can Tracing.end
let lastTreeStat = null;
let watchNames = null;          // PREFIX string
const nameSeen = new Map();     // nodeId -> last name (stability watch)
const nameAnomalies = [];       // {id, from, to} — a changed name == UAF-read signal

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  if (req.method === "POST" && url.pathname === "/progress") {
    let body = "";
    for await (const chunk of req) body += chunk;
    try { progress.push(JSON.parse(Buffer.from(body, "base64").toString("utf8"))); }
    catch (e) { progress.push({ bad: String(e).slice(0, 80) }); }
    res.writeHead(204).end();
    return;
  }
  if (req.method === "POST" && url.pathname === "/collect") {
    let body = "";
    for await (const chunk of req) body += chunk;
    try {
      serverResult = JSON.parse(Buffer.from(body, "base64").toString("utf8"));
      res.writeHead(204).end();
      resolveResult({ ok: true, result: serverResult });
    } catch (e) {
      res.writeHead(400).end(String(e));
      resolveResult({ ok: false, error: `bad payload: ${e}` });
    }
    return;
  }
  if (url.pathname === "/collect") {
    resolveResult({ ok: false, error: `page error: ${url.searchParams.get("e")}` });
    res.writeHead(204).end();
    return;
  }
  const file = join(ROOT, decodeURIComponent(url.pathname));
  if (!file.startsWith(ROOT)) { res.writeHead(403).end("forbidden"); return; }
  try {
    const raw = await readFile(file, "utf8");
    const body = extname(file) === ".html" ? INJECT + raw : raw;
    res.writeHead(200, {
      "Content-Type": { ".html": "text/html; charset=utf-8", ".js": "text/javascript" }[extname(file)] ?? "application/octet-stream",
      "Cache-Control": "no-store",
    });
    res.end(body);
  } catch { res.writeHead(404).end("not found"); }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;

const buildId = args.browser.split("/").slice(-3, -2).join("").replace(/\W/g, "");
const profileDir = `${process.env.LAB_PROFILE_DIR || "/tmp/opencode"}/ax-profile-${buildId}`;
const flags = [
  "--headless", "--no-sandbox",
  ...(args.gpu
    ? ["--use-angle=swiftshader", "--enable-unsafe-swiftshader", "--enable-gpu-rasterization"]
    : ["--disable-gpu"]),
  "--disable-background-networking", "--disable-component-extensions",
  "--disable-component-update", "--disable-sync", "--no-first-run",
  "--metrics-recording-only", "--disable-field-trial-config",
  "--remote-debugging-port=0",
  "--no-proxy-server",
  // force the renderer AX cache to be live without a real AT client
  "--force-renderer-accessibility",
  `--user-data-dir=${profileDir}`,
  "--remote-allow-origins=*",
];
if (args.jsFlags) flags.push(`--js-flags=${args.jsFlags}`);
flags.push(...args.extra, `http://127.0.0.1:${port}${args.page.startsWith("/") ? "" : "/"}${args.page}`);

let stderr = "";
let earlyResolved = false;
const onStderr = (d) => {
  stderr += d;
  if (!earlyResolved && /Received signal \d+|FATAL ERROR|==== JS stack trace|Fatal process out of memory/.test(stderr)) {
    earlyResolved = true;
    setTimeout(() => resolveResult({ ok: false, error: "renderer-crashed" }), 700);
  }
};
const chrome = spawn(args.browser, flags, { stdio: ["ignore", "pipe", "pipe"] });
chrome.stderr.on("data", onStderr);
chrome.stdout.on("data", onStderr);
chrome.on("exit", (code, sig) => { chromeExited = { code, sig }; });

// ---- CDP: wait for DevToolsActivePort, attach, hammer Accessibility ----
function cdpSession(wsUrl) {
  return new Promise((res, rej) => {
    const ws = new WebSocket(wsUrl);
    let id = 0;
    const pending = new Map();
    const send = (method, params = {}, sessionId) => new Promise((r2, j2) => {
      const m = ++id; pending.set(m, { res: r2, rej: j2 });
      ws.send(JSON.stringify({ id: m, method, params, ...(sessionId ? { sessionId } : {}) }));
      setTimeout(() => { if (pending.has(m)) { pending.delete(m); j2(new Error("to:" + method)); } }, 5000);
    });
    ws.onmessage = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.method && m.method.startsWith("Tracing.")) {
        traceDiag.methods[m.method] = (traceDiag.methods[m.method] || 0) + 1;
      }
      if (m.method === "Tracing.dataCollected" && m.params && m.params.value) {
        traceChunks.push(...m.params.value);
      }
      if (m.id && pending.has(m.id)) {
        const p = pending.get(m.id); pending.delete(m.id);
        m.error ? p.rej(new Error(JSON.stringify(m.error))) : p.res(m.result);
      }
    };
    ws.onopen = () => res({ ws, send });
    ws.onerror = (e) => rej(new Error("ws:" + e.message));
  });
}

async function axLoop() {
  // wait for the debugging port file
  const portFile = join(profileDir, "DevToolsActivePort");
  let dpPort = null;
  for (let i = 0; i < 100 && !dpPort; i++) {
    await new Promise((r) => setTimeout(r, 300));
    try { dpPort = readFileSync(portFile, "utf8").split("\n")[0].trim(); } catch {}
  }
  if (!dpPort) throw new Error("no DevToolsActivePort");
  const ver = await (await fetch(`http://127.0.0.1:${dpPort}/json/version`)).json();
  const { ws, send } = await cdpSession(ver.webSocketDebuggerUrl);
    if (args.traceCats) {
    await send("Tracing.start", { categories: args.traceCats, options: "sampling-frequency=10000" });
    traceStarted = true;
    traceCtl = { send };
  }
const t = await send("Target.getTargets");
  const page = t.targetInfos.find((x) => x.type === "page");
  if (!page) throw new Error("no page target");
  const { sessionId } = await send("Target.attachToTarget", { targetId: page.targetId, flatten: true });
  await send("Accessibility.enable", {}, sessionId);
  watchNames = args.watchNames ?? null;
  // the AX-client loop: pull the full tree as fast as the interval allows —
  // every pull re-serializes names/descriptions and processes deferred updates
  while (!earlyResolved) {
    try {
      const tk = await send("Accessibility.getFullAXTree", {}, sessionId);
      axCalls++;
      {
        const hist = {};
        for (const n of tk.nodes) {
          const r = (n.role && n.role.value) || "?";
          hist[r] = (hist[r] || 0) + 1;
        }
        lastTreeStat = { nodes: tk.nodes.length, hist };
        if (watchNames) {
          for (const n of tk.nodes) {
            const nm = (n.name && n.name.value) || "";
            const ds = (n.description && n.description.value) || "";
            const val = nm.startsWith(watchNames) ? nm
                      : ds.startsWith(watchNames) ? "[desc]" + ds : null;
            if (val === null) continue;
            if (nm.startsWith(watchNames) || ds.startsWith(watchNames)) {
              const key = n.nodeId + (ds.startsWith(watchNames) ? "d" : "n");
              const prev = nameSeen.get(key);
              if (prev !== undefined && prev !== val) {
                if (nameAnomalies.length < 20)
                  nameAnomalies.push({ id: n.nodeId, from: prev.slice(0, 60), to: val.slice(0, 60) });
              }
              nameSeen.set(key, val);
            }
          }
        }
      }
    } catch (e) {
      axErrors++; axLastErr = String(e.message).slice(0, 100);
      await new Promise((r) => setTimeout(r, 500));
    }
    await new Promise((r) => setTimeout(r, axInterval));
  }
  if (args.traceCats) {
    try { await send("Tracing.end", {}); } catch (e) {}
    await new Promise((r) => setTimeout(r, 800));
  }
  try { ws.close(); } catch {}
}
axLoop().catch((e) => { axLastErr = "setup:" + String(e.message).slice(0, 100); });

const timeout = setTimeout(() => resolveResult({ ok: false, error: "timeout waiting for result" }), args.timeoutMs);
const outcome = await resultPromise;
clearTimeout(timeout);

// Tracing.dataCollected is flushed at Tracing.end — MUST run for every outcome
if (args.traceCats && traceCtl) {
  try { await traceCtl.send("Tracing.end", {}); } catch (e) {}
  await new Promise((r) => setTimeout(r, 1200));
}

await new Promise((r) => setTimeout(r, 400));
chrome.kill("SIGTERM");
await new Promise((r) => setTimeout(r, 600));
if (!chrome.killed) chrome.kill("SIGKILL");

server.close();
if (args.stderrPath) {
  await mkdir(dirname(args.stderrPath), { recursive: true });
  await writeFile(args.stderrPath, stderr);
}
const report = {
  page: args.page,
  browser: args.browser,
  driver: "ax-run (Accessibility.getFullAXTree loop)",
  ax: { calls: axCalls, errors: axErrors, lastErr: axLastErr },
  traceDiag: { cats: args.traceCats ?? null, started: traceStarted, chunks: traceChunks.length, methods: traceDiag.methods },
  lastTreeStat,
  nameAnomalies: nameAnomalies.length ? nameAnomalies : undefined,
  namesWatched: watchNames ?? undefined,
  ok: outcome.ok,
  error: outcome.error ?? null,
  result: outcome.result ?? null,
  chromeExit: chromeExited,
  progress,
  stderrBytes: stderr.length,
};
if (args.traceCats && traceChunks.length) {
  const tracePath = args.out ? args.out.replace(/\.json$/, ".trace.json") : null;
  if (tracePath) {
    await writeFile(tracePath, JSON.stringify({ traceEvents: traceChunks }) + "\n");
    report.traceFile = tracePath;
    report.traceEvents = traceChunks.length;
  }
}
if (args.out) {
  await mkdir(dirname(args.out), { recursive: true });
  await writeFile(args.out, JSON.stringify(report, null, 2) + "\n");
}
console.log(JSON.stringify(report, null, 2));
if (!outcome.ok) process.exit(outcome.error === "timeout waiting for result" ? 3 : 42);
process.exit(0);
