#!/usr/bin/env node
/**
 * Stage oracle: loads a URL in a specific Chrome build, collects the evidence
 * the testcase publishes in `window.__LAB_RESULT`, and reports whether the
 * renderer or the browser process died.
 *
 * All three stages (crash, leak, rce) run through this oracle; what each stage
 * proves is defined by the case entry file, not here (`docs/EXPLOITATION.md`).
 * With `--cores-dir` the process runs with `--disable-breakpad` in a dedicated
 * working directory so the kernel writes a core, which is then analysed with
 * gdb in batch mode (normal binary tooling only, `docs/GDB.md`).
 *
 * Usage:
 *   node harness/oracle.mjs --browser builds/155.0.8059.84/chrome-linux64/chrome \
 *        --url http://127.0.0.1:8000/cases/X/testcase.html --timeout 20000
 *   ... --cores-dir /path/to/cores --core-out report.core.txt --keep-core true
 */
import { chromium } from "playwright-core";
import { writeFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { findGdb, findCore, analyzeCore, digest, dropCore } from "./lib/crash-report.mjs";

function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i += 2) {
    const key = argv[i].replace(/^--/, "");
    out[key] = argv[i + 1];
  }
  return out;
}

const args = parseArgs(process.argv);
const browserPath = args.browser;
const url = args.url;
const timeout = Number(args.timeout ?? 20000);
const iterations = Number(args.iterations ?? 1);
const headed = args.headed === "true";
const extraFlags = (args.flags ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

if (!browserPath || !url) {
  console.error(
    "usage: oracle.mjs --browser <path> --url <url> [--timeout ms] [--iterations n] [--flags a,b] [--cores-dir <dir>] [--core-out <file>] [--keep-core true]",
  );
  process.exit(2);
}

// Optional kernel core dumps: run in a dedicated directory (the core lands in
// the crashing process's cwd), disable Crashpad, analyse with gdb afterwards.
let coresDir = null;
if (args["cores-dir"]) {
  try {
    coresDir = resolve(args["cores-dir"]);
    mkdirSync(coresDir, { recursive: true });
    process.chdir(coresDir);
  } catch {
    coresDir = null; // best effort: the run continues without cores
  }
}
const keepCore = args["keep-core"] === "true";
const coreOut = args["core-out"] ?? null;

const DEFAULT_FLAGS = [
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-background-networking",
  "--disable-component-update",
  "--disable-sync",
  "--metrics-recording-only",
  "--disable-features=Translate,OptimizationHints,MediaRouter",
];

const report = {
  browser: browserPath,
  url,
  iterations,
  startedAt: new Date().toISOString(),
  crashed: false,
  crashType: null,
  results: [],
  console: [],
  pageErrors: [],
  core: null,
  durationMs: 0,
};

const started = Date.now();
let browser;

try {
  browser = await chromium.launch({
    executablePath: browserPath,
    headless: !headed,
    args: [...DEFAULT_FLAGS, ...(coresDir ? ["--disable-breakpad"] : []), ...extraFlags],
  });

  let disconnected = false;
  browser.on("disconnected", () => {
    disconnected = true;
  });

  for (let i = 0; i < iterations; i++) {
    const context = await browser.newContext();
    const page = await context.newPage();

    page.on("console", (msg) => {
      if (report.console.length < 200) {
        report.console.push({ type: msg.type(), text: msg.text().slice(0, 500) });
      }
    });
    page.on("pageerror", (err) => {
      report.pageErrors.push(String(err).slice(0, 500));
    });
    page.on("crash", () => {
      report.crashed = true;
      report.crashType = "renderer";
    });

    try {
      await page.goto(url, { waitUntil: "load", timeout });
      // The testcase publishes its verdict in window.__LAB_RESULT.
      const deadline = Date.now() + timeout;
      let result = null;
      while (Date.now() < deadline) {
        result = await page
          .evaluate(() => window.__LAB_RESULT ?? null)
          .catch(() => null);
        if (result) break;
        await page.waitForTimeout(100);
      }
      report.results.push({ iteration: i, result });
    } catch (err) {
      const message = String(err);
      report.pageErrors.push(message.slice(0, 500));
      if (/crash|Target closed|Protocol error|disconnected/i.test(message)) {
        report.crashed = true;
        report.crashType = report.crashType ?? "renderer-or-browser";
      }
      report.results.push({ iteration: i, result: null, error: message.slice(0, 300) });
    }

    await context.close().catch(() => {});
    if (disconnected) break;
  }
} catch (err) {
  report.crashed = true;
  report.crashType = "browser-launch-or-connection";
  report.pageErrors.push(String(err).slice(0, 500));
} finally {
  await browser?.close().catch(() => {});
}

report.durationMs = Date.now() - started;

// Core analysis (normal tooling only): gdb batch over the newest core this
// run produced — cores from earlier runs (kept with --keep-core) are ignored.
if (coresDir) {
  const core = findCore(coresDir, started);
  if (core) {
    report.crashed = true;
    report.crashType = report.crashType ?? "core-dump";
    const res = analyzeCore({ gdb: findGdb(args.gdb), binary: browserPath, core });
    report.core = {
      file: core,
      gdbAvailable: res.available,
      signal: res.signal ?? null,
      digest: res.available ? digest(res.text) : res.text,
    };
    if (coreOut) writeFileSync(coreOut, res.text + "\n");
    if (!keepCore) dropCore(core);
  } else {
    report.core = { file: null, note: `no core file in ${coresDir}` };
  }
}

if (args.out) writeFileSync(args.out, JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify(report, null, 2));

// exit code: 0 = no crash, 42 = crash detected (easy to script against)
process.exit(report.crashed ? 42 : 0);
