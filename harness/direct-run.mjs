#!/usr/bin/env node
/**
 * Direct (no-Playwright) driver: launches Chrome from the shell so the
 * renderer's stderr — V8 --trace-opt/--trace-deopt, %DebugPrint, flag
 * warnings — is captured verbatim, serves the case page with an injected
 * result beacon, and collects window.__LAB_RESULT via POST.
 *
 * This closes the standing "renderer stderr is unreachable from the harness"
 * item (Playwright does not forward it headless).
 *
 * Usage:
 *   node harness/direct-run.mjs cases/CVE-2026-3910/testcase.html \
 *     --browser builds/146.0.7680.72/chrome-linux64/chrome \
 *     --js-flags "--allow-natives-syntax --turbolev --turbofan --trace-opt --trace-deopt" \
 *     --out findings/raw/CVE-2026-3910.direct.72.json \
 *     --stderr findings/raw/CVE-2026-3910.direct.72.stderr.txt
 *
 * Exit code: 0 = result collected, 42 = chrome crashed before reporting,
 * 3 = timeout waiting for the result.
 */
import { createServer } from "node:http";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
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
    else if (a === "--extra") out.extra.push(argv[++i]);
    else if (!out.page) out.page = a;
  }
  return out;
}

const args = parseArgs(process.argv);
if (!args.page || !args.browser) {
  console.error("usage: direct-run.mjs <page-under-root> --browser <path> [--js-flags \"...\"] [--out f] [--stderr f]");
  process.exit(2);
}
if (!existsSync(args.browser)) {
  console.error(`browser not found: ${args.browser}`);
  process.exit(2);
}

// The poller is injected at the very top of the page: it waits for
// window.__LAB_RESULT and POSTs it same-origin (no CORS, no case changes).
const INJECT = `<script>(function(){
var iv=setInterval(function(){
  if(window.__LAB_RESULT){
    clearInterval(iv);
    try{
      var b=btoa(unescape(encodeURIComponent(JSON.stringify(window.__LAB_RESULT))));
      navigator.sendBeacon('/collect',b)||fetch('/collect',{method:'POST',body:b});
    }catch(e){fetch('/collect?e='+encodeURIComponent(String(e)));}
  }
},50);
setTimeout(function(){clearInterval(iv);fetch('/collect?e=timeout');},120000);
})();</script>`;

let resolveResult;
const resultPromise = new Promise((r) => { resolveResult = r; });
let serverResult = null;
let chromeExited = null;

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  console.error(`[req] ${req.method} ${url.pathname}${url.search.slice(0, 60)}`);

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

  // serve the case page (and siblings) from ROOT with the injected poller
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
  } catch {
    res.writeHead(404).end("not found");
  }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;

const flags = [
  "--headless", "--no-sandbox", "--disable-gpu",
  "--disable-background-networking", "--disable-component-extensions",
  "--disable-component-update", "--disable-sync", "--no-first-run",
  "--metrics-recording-only", "--disable-field-trial-config",
  // keep the browser pinned (Chrome 120 headless exits once idle without an
  // automation endpoint) and never route the local lab server through a proxy
  "--remote-debugging-port=0",
  "--no-proxy-server",
  // profile keyed by build: an older Chrome refuses a newer version's profile
  `--user-data-dir=/tmp/opencode/direct-profile-${args.browser.split("/").slice(-3, -2).join("").replace(/\W/g, "")}`,
  "--remote-allow-origins=*",
];
if (args.jsFlags) flags.push(`--js-flags=${args.jsFlags}`);
flags.push(...args.extra, `http://127.0.0.1:${port}${args.page.startsWith("/") ? "" : "/"}${args.page}`);

let stderr = "";
const chrome = spawn(args.browser, flags, { stdio: ["ignore", "pipe", "pipe"] });
chrome.stderr.on("data", (d) => { stderr += d; });
chrome.stdout.on("data", (d) => { stderr += d; });
chrome.on("exit", (code, sig) => { chromeExited = { code, sig }; });

const timeout = setTimeout(() => resolveResult({ ok: false, error: "timeout waiting for result" }), args.timeoutMs);
const outcome = await resultPromise;
clearTimeout(timeout);

// give trailing stderr (deopt/trace lines) a moment, then stop chrome
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
  jsFlags: args.jsFlags ?? null,
  ok: outcome.ok,
  error: outcome.error ?? null,
  result: outcome.result ?? null,
  chromeExit: chromeExited,
  stderrBytes: stderr.length,
};
if (args.out) {
  await mkdir(dirname(args.out), { recursive: true });
  await writeFile(args.out, JSON.stringify(report, null, 2) + "\n");
}
console.log(JSON.stringify(report, null, 2));
if (!outcome.ok) process.exit(outcome.error === "timeout waiting for result" ? 3 : 42);
process.exit(0);
