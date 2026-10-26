#!/usr/bin/env node
// AX-tree inspector: loads a page, pulls the full AX tree via CDP, reports
// nodes whose role/nodeType relate to image-map internals (img/map/area) and
// their parent chain. Used to verify GetAXImageForMap preconditions live.
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const page = process.argv[2];
const browser = process.argv[3] || "builds/155.0.8059.84/chrome-linux64/chrome";
const profile = "/tmp/opencode/axprobe-profile";

const flags = [
  "--headless", "--no-sandbox", "--disable-gpu",
  "--disable-background-networking", "--no-first-run", "--metrics-recording-only",
  "--remote-debugging-port=0", "--no-proxy-server",
  "--force-renderer-accessibility",
  `--user-data-dir=${profile}`, "--remote-allow-origins=*",
  `http://127.0.0.1:1${page}`, // unreachable: we Runtime.evaluate content instead
];
const chrome = spawn(browser, flags, { stdio: ["ignore", "pipe", "pipe"] });
let stderr = "";
chrome.stderr.on("data", (d) => { stderr += d; });

const portFile = join(profile, "DevToolsActivePort");
let dpPort = null;
for (let i = 0; i < 100 && !dpPort; i++) {
  await new Promise((r) => setTimeout(r, 300));
  try { dpPort = readFileSync(portFile, "utf8").split("\n")[0].trim(); } catch {}
}
const ver = await (await fetch(`http://127.0.0.1:${dpPort}/json/version`)).json();
const ws = new WebSocket(ver.webSocketDebuggerUrl);
let id = 0; const pending = new Map();
const send = (method, params = {}, sessionId) => new Promise((res, rej) => {
  const m = ++id; pending.set(m, { res, rej });
  ws.send(JSON.stringify({ id: m, method, params, ...(sessionId ? { sessionId } : {}) }));
  setTimeout(() => { if (pending.has(m)) { pending.delete(m); rej(new Error("to:" + method)); } }, 8000);
});
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.rej(new Error(JSON.stringify(m.error))) : p.res(m.result); }
};
await new Promise((r) => { ws.onopen = r; });
const t = await send("Target.getTargets");
const pageT = t.targetInfos.find((x) => x.type === "page");
const { sessionId } = await send("Target.attachToTarget", { targetId: pageT.targetId, flatten: true });

const html = readFileSync(page, "utf8").replace(/^[\s\S]*?<body>/, "").replace(/<script>[\s\S]*?<\/script>/g, "");
await send("Runtime.evaluate", { expression: `document.body.innerHTML = ${JSON.stringify(html)}` }, sessionId);
await new Promise((r) => setTimeout(r, 500));
await send("Accessibility.enable", {}, sessionId);
const tree = await send("Accessibility.getFullAXTree", {}, sessionId);
const byId = new Map(tree.nodes.map((n) => [n.nodeId, n]));
const show = (n, indent) => {
  const name = (n.name && n.name.value) || "";
  const role = (n.role && n.role.value) || "";
  console.log(`${indent}${role} "${String(name).slice(0, 30)}" nodeType=${n.nativeDOMNodeType || "?"} ignored=${n.ignored || false}`);
};
for (const n of tree.nodes) {
  const name = (n.name && n.name.value) || "";
  const role = (n.role && n.role.value) || "";
  if (/image|link|GenericContainer|Map/i.test(role) || /area|map/i.test(String(n.nativeDOMNodeType))) {
    show(n, "");
    let p = byId.get(n.parentId);
    let depth = 1;
    while (p && depth < 4) { show(p, "  ".repeat(depth) + "└ "); p = byId.get(p.parentId); depth++; }
  }
}
console.log("total nodes:", tree.nodes.length);
ws.close();
chrome.kill("SIGKILL");
process.exit(0);
