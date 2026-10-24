# chrome2shell — Chrome CVE research lab

> **This repository does NOT contain exploits or an RCE chain.** Despite the
> name, it is a crash-only reproduction lab and exploitability assessment:
> CVE inventory, patches, root cause and vulnerable-vs-patched differential.
> It contains no exploit code, no read/write primitives and no sandbox escapes.
>
> Intended use: defensive research and patch verification in owned, authorized
> environments.

A reproducible lab to study and **verify** critical Google Chrome CVEs using
only public information: official advisories, crbug.com bug IDs and the fix
commits.

> **Scope:** defensive, crash-only lab. It contains no exploits, no RCE and no
> sandbox evasion. The goal is to answer one question: *can the flaw be
> reproduced on the affected build and confirmed fixed on the patched one?*

---

## TL;DR — what we found

**Scope is RCE-first.** The lab only keeps flaws that can plausibly lead to
code execution in the browser (memory corruption in V8/WebAssembly, GPU/Skia,
Mojo/IPC, media, or a sandbox escape). Bugs that are only policy bypasses, UI
spoofing, info leaks or DoS are catalogued but not worked on.

The official *Stable updates* feed was paged back to **2023-10-01** (three
years). That yields:

| Dataset | Rows | What it is |
|---------|------|------------|
| `data/cves.json` | **1,199** | every `High`/`Critical` stable CVE since 2023-10 |
| `data/rce_cves.json` | **879** | memory-safety bugs with an RCE path, or exploited in the wild |
| `data/rce_priority.json` | **142** | `Critical` memory-safety + all 20 in-the-wild CVEs |

Classification is a documented heuristic (`scripts/sync_cves.py`): the bug
class comes from the advisory text ("Use after free in Prerender"), and it is
ranked `high` when the component is a direct code-execution surface, `medium`
when the bug still needs a reachable trigger or an extra primitive, and `low`
for non-memory-safety classes and plain out-of-bounds *reads*.

The two most recent releases (October 15 and 20, 2026) contain **7 CVEs rated
`Critical`**, which became the first lab cases:

| CVE | Component | Type | Bug ID | Fix commit | Reproducible |
|-----|-----------|------|--------|-----------|--------------|
| CVE-2026-110922 | Prerender | UAF (browser) | 568719351 | `d50992ebe4` | ⚠️ blocked (see below) |
| CVE-2026-113341 | Skia / Ganesh | UAF (driver) | 569165786 | `02b14267` (skia) | ❌ Imagination hardware |
| CVE-2026-113279 | Accessibility | Mem. corruption | 570093145 | `83ce9f18d7` | 🧪 a11y stress |
| CVE-2026-113072 | CSS / LCP | Mem. corruption | 570638836 | `73dd2febfa` | ✅ behavioral |
| CVE-2026-113280 | Paint / caret | Mem. corruption | 570740320 | `3ab9f85874` | 🧪 paint stress |
| CVE-2026-113271 | Accessibility | UAF (StringImpl) | 571618833 | `15248c94bc` | 🧪 a11y stress |
| CVE-2026-113303 | WebRTC / audio | Mem. corruption | 574041825 | `e193ceb7de` | 🧪 audio stress |

**Methodological finding:** although the crbug.com bugs remain restricted and
there are no public PoCs, the advisory publishes the **bug ID**, and the fix
lands in a public repo with `Fixed: <bug_id>` in the commit message. That makes
it possible to recover the exact patch and derive the root cause.
`scripts/find_fixes.py` automates it: 7/7 found.

### Exploited in the wild since 2023-10

These 20 are the highest-priority targets: Google's own advisory says an
exploit exists in the wild. They are the natural first backlog for the lab.

| Date | CVE | Component | Fixed in |
|------|-----|-----------|----------|
| 2026-09-03 | CVE-2026-85046 | Type confusion in V8 | 152.0.7977.82 |
| 2026-03-31 | CVE-2026-5281 | Use after free in Dawn | 146.0.7680.177 |
| 2026-03-13 | CVE-2026-3909 | Out of bounds write in Skia | 146.0.7680.80 |
| 2026-03-12 | CVE-2026-3910 | Inappropriate implementation in V8 | 146.0.7680.75 |
| 2026-02-13 | CVE-2026-2441 | Use after free in CSS | 145.0.7632.75 |
| 2025-12-10 | CVE-2025-14174 | Out of bounds memory access in ANGLE | 143.0.7499.109 |
| 2025-11-17 | CVE-2025-13223 | Type confusion in V8 | 142.0.7444.175 |
| 2025-09-17 | CVE-2025-10585 | Type confusion in V8 | 140.0.7339.185 |
| 2025-07-15 | CVE-2025-6558 | Incorrect validation in ANGLE and GPU | 138.0.7204.157 |
| 2025-06-30 | CVE-2025-6554 | Type confusion in V8 | 138.0.7204.96 |
| 2025-06-02 | CVE-2025-5419 | Out of bounds read and write in V8 | 137.0.7151.68 |
| 2025-03-25 | CVE-2025-2783 | Incorrect handle in Mojo (Windows) | 134.0.6998.177 |
| 2025-03-10 | CVE-2025-24201 | Out of bounds write in GPU (Mac) | 134.0.6998.88 |
| 2024-05-23 | CVE-2024-5274 | Type confusion in V8 | 125.0.6422.112 |
| 2024-05-15 | CVE-2024-4947 | Type confusion in V8 | 125.0.6422.60 |
| 2024-05-13 | CVE-2024-4761 | Out of bounds write in V8 | 124.0.6367.207 |
| 2024-05-09 | CVE-2024-4671 | Use after free in Visuals | 124.0.6367.201 |
| 2024-01-16 | CVE-2024-0519 | Out of bounds memory access in V8 | 120.0.6099.234 |
| 2023-12-20 | CVE-2023-7024 | Heap buffer overflow in WebRTC | 120.0.6099.129 |
| 2023-11-28 | CVE-2023-6345 | Integer overflow in Skia | 119.0.6045.199 |

### Backlog triage: newest in-the-wild CVEs (patches recovered)

Working newest-first, the fix commit has been recovered for the 5 most recent
in-the-wild entries. For vendored components the matching chromium commit is
only an **autoroll**, so `scripts/find_fixes.py` now follows the roll into the
submodule (`V8`, `Dawn`) and picks the individual commit that references the
bug. The roll is kept as `patches/<CVE>.roll.patch` for provenance.

| Advisory | CVE | Component | Root-cause commit | Repo |
|----------|-----|-----------|-------------------|------|
| 2026-09-03 | CVE-2026-85046 | Type confusion in V8 (sort inlining) | `e0562d87ad` | v8/v8 |
| 2026-03-31 | CVE-2026-5281 | Use after free in Dawn (wire) | `3c890398bd` | google/dawn |
| 2026-03-13 | CVE-2026-3909 | Out of bounds write in Skia (atlas) | `0cab3e4ee3` | google/skia |
| 2026-03-12 | CVE-2026-3910 | Inappropriate implementation in V8 (Maglev Phi) | `7076ba135f` | v8/v8 |
| 2026-02-13 | CVE-2026-2441 | Use after free in CSS (font feature values) | `e045399a1e` | chromium |

All 12 recovered patches (7 Oct-2026 cases + these 5) contain enough context to
derive a crash-only reproducer; 10 of them add or change a regression test.
That test is the specification used for the next round of cases.

**CVE-2026-110922 is not missing from this backlog:** it is the prerender UAF in
the October table above. Its patch (`d50992ebe4`) is recovered, and its
CDP-free driver is `harness/selfdrive-110922.mjs`. What is still missing is the
synchronous eviction: the stalled prerender host is alive at `history.back()`
(`open=1`), the BFCache restore is evicted ~57 ms later by Service Worker
activation, and a 600–1200 ms delay sweep produced 0 crashes in 9 runs. The
deterministic reproduction is the patch's C++ test, which needs a debug build
and gdb breakpoints, not ASAN.

### Debugging without ASAN

Release binaries can still be used with normal tooling: the harness enables
kernel core dumps, disables Crashpad, and analyses the core with `gdb` in batch
mode (`bt`, registers, faulting instruction, module map). Full instructions are
in [`docs/GDB.md`](docs/GDB.md); cores land in `findings/raw/` and are deleted
after analysis unless `--keep-core` is passed.

**Reality check on reproduction:** 6 of the 7 cases are memory corruptions that
do not reliably abort in `release` builds (no ASAN or DCHECKs). The lab is meant to
(1) confirm the vulnerable path, (2) compare vulnerable vs. patched builds and
(3) serve as a base for an ASAN build. Per-CVE details are in
[`findings/RESULTS.md`](findings/RESULTS.md) and
[`findings/EXPLOITABILITY.md`](findings/EXPLOITABILITY.md).

### CVE-2026-110922: what the lab established

Two findings are worth recording because they cost several wrong attempts:

1. **DevTools disables prerendering.** Any CDP session without tab-target
   support makes `devtools_instrumentation::IsPrerenderAllowed()` return false,
   and Chromium rejects every speculation rule with `PrerenderFinalStatus` 69
   (`kPrerenderingDisabledByDevTools`, not reuse). A Playwright-driven browser
   can never reach this bug; `harness/selfdrive-110922.mjs` launches Chromium
   with no debugging port and lets the page drive itself.
2. **The eviction is asynchronous.** Without DevTools the prerender really
   runs and the sequence completes, but Service Worker v2 activation that
   evicts the BFCache entry happens ~1 s after `history.back()`, and cancelling
   the stalled prerender does not synchronously start the pending one. The
   destroy never lands inside `BeginNavigation()`: 0 crashes in 20+ attempts.

The canonical reproduction is the patch's own
`PrerenderBackForwardCacheBrowserTest.EvictBackForwardCacheDuringPrerenderActivationCheck`
on an ASAN build. No exploit code is involved or needed.

---

## Layout

```
chrome-cve-lab/
├── data/
│   ├── cves.json          # High/Critical inventory since 2023-10
│   ├── rce_cves.json      # RCE-relevant subset
│   ├── rce_priority.json  # Critical memory-safety + in-the-wild
│   ├── fixes.json         # CVE -> fix commit + patch
│   └── cache/feed.json    # paged feed snapshot (--offline mode)
├── scripts/
│   ├── sync_cves.py       # Chrome Releases RSS -> data/cves.json
│   ├── find_fixes.py      # bug ID -> fix commit -> patches/<CVE>.patch
│   ├── fetch_chrome.py    # download an exact Chrome for Testing version
│   └── setup_asan.sh      # Chromium ASAN build (multi-hour, optional)
├── harness/
│   ├── oracle.mjs         # load a URL and detect crashes (renderer/browser)
│   ├── run-case.mjs       # run a case on vulnerable vs. patched builds
│   ├── repro-110922.mjs   # CVE-2026-110922, Playwright driver (control only)
│   ├── selfdrive-110922.mjs  # CVE-2026-110922, CDP-free driver
│   ├── lib/scenario-server.mjs  # shared server + in-page orchestration
│   └── lib/crash-report.mjs     # core dump -> gdb batch report
├── cases/<CVE>/           # case.json + testcase.html + root-cause README
├── patches/               # fix patches (evidence)
├── docs/                  # ADDING_CVES.md, ASAN.md
└── findings/              # RESULTS.md, EXPLOITABILITY.md and JSON
```

Key documents:

- [`findings/RESULTS.md`](findings/RESULTS.md) — what was reproduced and what
  was not.
- [`findings/EXPLOITABILITY.md`](findings/EXPLOITABILITY.md) — per-CVE
  exploitability assessment (reachability, lifetime, mitigations, level).
- [`docs/GDB.md`](docs/GDB.md) — release-build crashing with core dumps and
  gdb, no ASAN build required.
- [`docs/ASAN.md`](docs/ASAN.md) — sanitizer build to characterize the UAFs
  (the strongest detector when a build is affordable).

## Requirements

- Node.js ≥ 20 and `npm install` (only `playwright-core`, no bundled browsers).
- Python 3.10+.
- ~400 MB of disk per Chrome for Testing build.
- Docker is not required. The Chrome binary runs directly.

## Usage

```bash
npm install

# 1. three-year inventory, then the RCE-focused views
python3 scripts/sync_cves.py --since 2023-10-01 --min-severity High
python3 scripts/sync_cves.py --since 2023-10-01 --min-severity High --rce-only --out data/rce_cves.json
python3 scripts/sync_cves.py --since 2023-10-01 --min-severity High --priority --out data/rce_priority.json

# 2. locate patches (bug ID -> commit -> patch)
python3 scripts/find_fixes.py

# 3. download the vulnerable build and the first patched one
python3 scripts/fetch_chrome.py 155.0.8059.84 156.0.8078.47

# 4. run one case (or all of them)
node harness/run-case.mjs CVE-2026-113072
node harness/run-case.mjs --all

# 5. CVE-2026-110922 without DevTools (prerendering is disabled under CDP)
node harness/selfdrive-110922.mjs --browser /usr/lib/chromium/chromium

# 6. on a crash, keep the core and inspect the gdb report
node harness/selfdrive-110922.mjs --browser ./builds/.../chrome --keep-core
cat findings/raw/CVE-2026-110922.attempt1.core.txt
```

The oracle exits `42` when it detects a crash and `0` otherwise. Results are
written to `findings/<CVE>.json` and `findings/raw/`.

> **Note:** the Chrome for Testing zip does not preserve Unix permissions.
> `fetch_chrome.py` restores them; if you extract it by hand, run
> `chmod +x chrome chrome_crashpad_handler chrome_sandbox` or the browser will
> abort at startup (`posix_spawn ... Permission denied`).

## Methodology

1. **Inventory** — the official *Stable updates* feed includes severity, CVE,
   component and bug ID.
2. **Patch** — `find_fixes.py` searches `repo:chromium/chromium <bug_id>` (with
   `google/skia`, `google/dawn`, `google/angle` as fallbacks) through the
   GitHub commit search API. The commit is saved as a `.patch`.
3. **Root cause** — read the diff (and its regression test, which usually
   describes the exact sequence).
4. **Testcase** — translate that sequence into HTML/JS that runs in the
   harness.
5. **Differential check** — same testcase on the vulnerable build and on the
   first patched one. Compare crashes and observable behavior.

## Limitations (important)

- **No ASAN.** Chrome for Testing ships `release` builds. A UAF may never
  abort. Reliable detection requires building Chromium with
  `is_asan=true is_debug=false` (or `is_msan`), which needs ~100 GB and hours.
  The harness already supports pointing a case at any binary via
  `case.json -> browser`.
- **Driver/hardware bugs.** CVE-2026-113341 lives in the Imagination driver;
  without that hardware it cannot be reproduced.
- **Browser-process bugs.** A UAF in the browser process shows up as a CDP
  disconnect, not as `page.on('crash')`; the oracle classifies it as
  `browser-launch-or-connection`.
- **Timing.** Several cases are races; they run with `iterations` and stress,
  but a "no crash" result **does not prove** the bug is absent.

## Adding a new CVE

```bash
python3 scripts/sync_cves.py --min-severity High --days 30
python3 scripts/find_fixes.py --cve CVE-2026-XXXXX
mkdir cases/CVE-2026-XXXXX   # copy a case.json and its testcase.html
node harness/run-case.mjs CVE-2026-XXXXX
```

See [`docs/ADDING_CVES.md`](docs/ADDING_CVES.md).

## References

- Chrome Releases: <https://chromereleases.googleblog.com/>
- Chrome Security (severity guidelines): <https://www.chromium.org/developers/severity-guidelines/>
- Chrome for Testing: <https://googlechromelabs.github.io/chrome-for-testing/>
- NVD: <https://nvd.nist.gov/>

## Disclaimer

Use only in your own, isolated environment. Do not point the harness at
third-party sites or distribute the testcases as exploits.

This repository is **not an exploit kit**: it contains no remote-code-execution
code, no read/write primitives and no sandbox escapes. The testcases only
exercise code paths to detect crashes and compare behavior between versions.
Any use to attack systems without authorization is outside the intended scope
and is the responsibility of whoever performs it.
