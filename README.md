# chrome2shell — Chrome CVE exploitation lab

> **Scope: crash → leak → RCE.** This is a full exploitation-development lab:
> each case is driven through three stages — a crash PoC, a leak PoC and an
> RCE PoC — and every stage is verified differentially against the first
> patched build.
>
> **No sanitizers.** Everything runs on the shipped `release` binaries using
> normal binary-debugging tools: `gdb`, kernel core dumps, `objdump`/`readelf`,
> `strace`, `perf`. Evidence is observable state, controlled register crashes
> and payload markers — never an ASAN report.
>
> Intended use: defensive research and patch verification in owned, authorized
> environments. Targets are the pinned local builds in `builds/` served from
> `127.0.0.1`, and every CVE here is already patched upstream.

A reproducible lab to study and **exploit** critical Google Chrome CVEs using
only public information: official advisories, crbug.com bug IDs and the fix
commits — then to prove the exploit path is cut by the patch.

> **Scope of "exploit":** the ladder is crash → leak → primitives →
> control-flow hijack → lab-marker payload, inside the renderer process (the
> advisory's own scope). Host-level sandbox escape is a separate scope, only
> relevant for CVEs whose advisory is a sandbox bug; none of the current cases
> is one. See [`docs/EXPLOITATION.md`](docs/EXPLOITATION.md) for the full
> methodology and evidence rules.

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

| CVE | Component | Type | Bug ID | Fix commit | Stage status |
|-----|-----------|------|--------|-----------|--------------|
| CVE-2026-110922 | Prerender | UAF (browser) | 568719351 | `d50992ebe4` | ⛔ stage 1 blocked (see below) |
| CVE-2026-113341 | Skia / Ganesh | UAF (driver) | 569165786 | `02b14267` (skia) | ⛔ no Imagination hardware |
| CVE-2026-113279 | Accessibility | Mem. corruption | 570093145 | `83ce9f18d7` | 🧪 stage 1 (a11y stress) |
| CVE-2026-113072 | CSS / LCP | Mem. corruption | 570638836 | `73dd2febfa` | 🟡 stage 1–2 (exposure) |
| CVE-2026-113280 | Paint / caret | Mem. corruption | 570740320 | `3ab9f85874` | 🧪 stage 1 (paint stress) |
| CVE-2026-113271 | Accessibility | UAF (StringImpl) | 571618833 | `15248c94bc` | 🧪 stage 1 (a11y stress) |
| CVE-2026-113303 | WebRTC / audio | Mem. corruption | 574041825 | `e193ceb7de` | 🧪 stage 1 (audio stress) |

The full per-CVE, per-stage tracker (crash / leak / RCE columns and next
actions) is [`findings/STAGES.md`](findings/STAGES.md).

**Methodological finding:** although the crbug.com bugs remain restricted and
there are no public PoCs, the advisory publishes the **bug ID**, and the fix
lands in a public repo with `Fixed: <bug_id>` in the commit message. That makes
it possible to recover the exact patch and derive the root cause.
`scripts/find_fixes.py` automates it: 7/7 found. The patch is also the
specification for every later stage: it lists what the fix stops exposing,
stops re-entering and stops letting an attacker shape.

### The three stages

| Stage | Question | Evidence | Harness |
|-------|----------|----------|---------|
| **1. crash** | is the vulnerable path reachable? | differential crash + core/`gdb` anatomy (or a live `gdb` observation of corrupted state) | `run-case.mjs --stage crash` |
| **2. leak** | can the page observe what it must not? | values published in `__LAB_RESULT`, corroborated in `gdb`, absent on the patched build | `run-case.mjs --stage leak` |
| **3. RCE** | can we choose what executes? | ladder rungs: shaping → primitives → arbitrary R/W → chosen `rip` → lab-marker payload | `run-case.mjs --stage rce` |

Every stage obeys the same rule: **the PoC must fail on the first patched
build.** Methodology, tool matrix and per-CVE plans:
[`docs/EXPLOITATION.md`](docs/EXPLOITATION.md).

### Completed PoCs (evidence in-tree, no RCE claim)

| CVE | Stage | What it does | Evidence |
|-----|-------|--------------|----------|
| **CVE-2026-85046** — V8 sort type confusion (in-the-wild, 2026-09) | **1 — differential trigger** | reproduces the upstream mjsunit assertion from plain JS: `[8595714,…]` on `152.0.7977.75` vs `[{},{}]` on `.82` | `cases/CVE-2026-85046/testcase.html`, `findings/raw/CVE-2026-85046.crash.*.json` |
| **CVE-2026-85046** | **2 — addrof leak PoC** | object → compressed-pointer integer:10 values in cage range, **same object → same value**, neighbour pair = **16 B** (address granularity); patched build leaks0 | `cases/CVE-2026-85046/poc-leak.html`, `findings/raw/CVE-2026-85046.leak.*.json` |
| **CVE-2026-3910** — Maglev phi untagging (in-the-wild, TAG, 2026-03) | **1 — crash PoC** | write barrier elided on Smi *feedback*; `trigger(0x10000000)` retags the untagged Int32 loop-phi (0x50000000 > Smi range) to a young HeapNumber stored into the OLD object with **no write barrier** → minor GC frees it → reading `o.x` = deterministic renderer crash (V8 fatal, core `ud2`); phase-mapped to the UAF read; `155.0.8059.84` runs clean | `cases/CVE-2026-3910/poc-wb-uaf.html`, `findings/raw/CVE-2026-3910.crash.*.json` + cores (verdict=reproduced) |
| **CVE-2026-2441** — CSS font-feature-values UAF (in-the-wild, 2026-02) | **1 — crash PoC** | iterates `rule.styleset` while deleting + mass-setting (aliases HashMap rehash → dangling iterator): renderer **SEGV 4/4** on `145.0.7632.67`; core shows `rax=0x4055210000000000` (IEEE754 double bits deref'd as pointer) | `cases/CVE-2026-2441/testcase.html`, `findings/raw/CVE-2026-2441.crash.*.json` + 4 cores |
| **CVE-2026-3910** | **3 — full chain: arbitrary heap R/W** | deterministic header locator (first 8 char bytes == known `obj[k+2]` bits, k varies per run) → forge `o.x` into a PACKED_DOUBLE JSArray → **OOB read returns real heap words** (scan_target's `{map,props,elements,len}` header) and **arbitrary write verified** (`o.x[8]=1337.1337` write+readback) — the complete published chain (UAF → scan → fakeobj → cage R/W) on `146.0.7680.72` | `cases/CVE-2026-3910/poc-rce.html`, `findings/raw/CVE-2026-3910.rce.vulnerable.json` |
| **CVE-2026-3910** | **2 — leak PoC (published exploit)** | dangling `o.x` read as a long string overlapping the heap: signature scan finds `0x3ff19999` (double 1.1) 3/3 runs → leaks the PACKED_DOUBLE **JSArray map (static root)** and the **elements heap pointer** (varies per run = ASLR material) | `cases/CVE-2026-3910/poc-leak-min.html`, `findings/raw/CVE-2026-3910.leak.vulnerable.json` |
| **CVE-2026-2441** | **2 — UAF-read leak PoC** | after the free, reclaim the bucket buffer with24 foreign `@font-feature-values` maps (same size class): the stale iterator returns **foreign keys that never existed in the original map** (`f0x1`, `f13x2`, …) = read-after-free of replaced memory | `cases/CVE-2026-2441/poc-leak.html`, `findings/raw/CVE-2026-2441.leak.vulnerable.json` |
| CVE-2026-113072 — CSS/LCP (Oct release) | 1–2 — exposure | LCP hands out the hidden `::before` node on155, `null` on156 | `cases/CVE-2026-113072/poc-leak.html` |

**Stage 3 (RCE) has no completed PoC yet.** The chain campaign — 85046's
addrof + CVE-2026-3910's raw-bit store on `146.0.7680.72` (a build vulnerable
to both) — is in progress with the d8 debug toolchain; the table below covers
the October release cases, and **per-stage status for every CVE (including
85046/3910) lives in [`findings/STAGES.md`](findings/STAGES.md)**.

### Exploited in the wild since 2023-10

These 20 are the highest-priority targets: Google's own advisory says an
exploit exists in the wild. They are the natural backlog for the RCE ladder
(the V8 type confusions in it are the most ladder-friendly class).

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

| Advisory | CVE | Component | Root-cause commit | Repo | Ladder notes |
|----------|-----|-----------|-------------------|------|--------------|
| 2026-09-03 | CVE-2026-85046 | Type confusion in V8 (sort inlining) | `e0562d87ad` | v8/v8 | first RCE-ladder target — **stages 1–2 done** (crash-differential + addrof leak) |
| 2026-03-31 | CVE-2026-5281 | Use after free in Dawn (wire) | `3c890398bd` | google/dawn | stage 1 first |
| 2026-03-13 | CVE-2026-3909 | Out of bounds write in Skia (atlas) | `0cab3e4ee3` | google/skia | write primitive |
| 2026-03-12 | CVE-2026-3910 | Inappropriate implementation in V8 (Maglev Phi untagging) | `7076ba135f` | v8/v8 | **stage 1 reproduced** (WB-elision UAF, public root-cause PoC ported); stages 2–3 next |
| 2026-02-13 | CVE-2026-2441 | Use after free in CSS (font feature values) | `e045399a1e` | chromium | **stages 1–2 done** (SEGV differential + UAF-read leak via foreign-buffer reclaim) |

All 12 recovered patches (7 Oct-2026 cases + these 5) contain enough context to
derive a reproducer; 10 of them add or change a regression test. That test is
the specification used for the next round of cases.

**CVE-2026-110922 is not missing from this backlog:** it is the prerender UAF in
the October table above. Its patch (`d50992ebe4`) is recovered, and its
CDP-free driver is `harness/selfdrive-110922.mjs`. What is still missing is the
synchronous eviction: the stalled prerender host is alive at `history.back()`
(`open=1`), the BFCache restore is evicted ~57 ms later by Service Worker
activation, and a 600–1200 ms delay sweep produced 0 crashes in 9 runs. The
deterministic reproduction is the patch's C++ test, which needs a debug build
and `gdb` breakpoints (no sanitizer involved).

### Debugging with normal tools

Release binaries work with ordinary tooling: the harness enables kernel core
dumps, disables Crashpad, and analyses the core with `gdb` in batch mode
(`bt`, registers, faulting instruction, module map). Full instructions are in
[`docs/GDB.md`](docs/GDB.md) (including live breakpoints and watchpoints for
the leak and RCE stages); cores land in `findings/raw/` and are deleted after
analysis unless `--keep-core` is passed.

**Reality check on stage 1:** 6 of the 7 cases are memory corruptions that do
not reliably fault in `release` builds (no ASAN and no DCHECKs). The lab's
answer is not a rebuilt binary: it is heap shaping to force reuse, `gdb`
breakpoints placed on the exact lines the patch changes, and watchpoints over
the dangling slot (`docs/EXPLOITATION.md` §1). The lab is meant to (1) confirm
the vulnerable path, (2) compare vulnerable vs. patched builds, and (3) carry
each case up the ladder. Per-CVE details are in
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
under `gdb` breakpoints in `NavigationRequest::BeginNavigation`. No ASAN, no
sanitizer build.

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
│   └── setup_asan.sh      # optional sanitizer build (NOT part of the workflow)
├── harness/
│   ├── oracle.mjs         # stage oracle: load a URL, collect evidence, detect crashes
│   ├── run-case.mjs       # --stage crash|leak|rce on vulnerable vs. patched builds
│   ├── repro-110922.mjs   # CVE-2026-110922, Playwright driver (control only)
│   ├── selfdrive-110922.mjs  # CVE-2026-110922, CDP-free driver
│   ├── lib/scenario-server.mjs  # shared server + in-page orchestration
│   └── lib/crash-report.mjs     # core dump -> gdb batch report
├── cases/<CVE>/
│   ├── case.json          # builds, flags, and stages.<stage> = {entry, status}
│   ├── testcase.html      # stage 1: crash/behavior trigger
│   ├── poc-leak.html      # stage 2: leak/exposure PoC (when started)
│   ├── poc-rce.html       # stage 3: RCE PoC (when started)
│   └── README.md          # root cause, relevant diff, stage status
├── patches/               # fix patches (evidence + PoC specification)
├── docs/
│   ├── EXPLOITATION.md    # THE scope document: crash → leak → RCE methodology
│   ├── ADDING_CVES.md     # how to add a case (with stage files)
│   ├── GDB.md             # core dumps, batch and live debugging, watchpoints
│   └── ASAN.md            # optional reference only (not used by this lab)
└── findings/
    ├── STAGES.md          # per-CVE stage tracker (crash/leak/RCE columns)
    ├── RESULTS.md         # what was reproduced and what was not
    ├── EXPLOITABILITY.md  # per-CVE exploitability assessment
    └── raw/               # oracle JSON, gdb reports, cores (--keep-core)
```

Key documents:

- [`docs/EXPLOITATION.md`](docs/EXPLOITATION.md) — the methodology for the
  three stages, evidence rules, toolchain, per-CVE plans.
- [`findings/STAGES.md`](findings/STAGES.md) — where every CVE stands on the
  crash / leak / RCE ladder and the next action.
- [`findings/RESULTS.md`](findings/RESULTS.md) — what was reproduced and what
  was not.
- [`findings/EXPLOITABILITY.md`](findings/EXPLOITABILITY.md) — per-CVE
  exploitability assessment (reachability, lifetime, mitigations, level).
- [`docs/GDB.md`](docs/GDB.md) — release-build crashing, core dumps, live
  breakpoints and watchpoints, no sanitizer build required.

## Requirements

- Node.js ≥ 20 and `npm install` (only `playwright-core`, no bundled browsers).
- Python 3.10+.
- `gdb` (the wrapper setup without root is documented in `docs/GDB.md`).
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
#    (--connections N parallelizes the fetch on slow links)
python3 scripts/fetch_chrome.py 155.0.8059.84 156.0.8078.47
python3 scripts/fetch_chrome.py 152.0.7977.75 152.0.7977.82 --connections 16  # CVE-2026-85046 pair

# 4. stage 1: crash / behavior, differentially
node harness/run-case.mjs CVE-2026-113072
node harness/run-case.mjs --all

# stage 2 and 3 use the same runner with the case's poc-leak/poc-rce entries
node harness/run-case.mjs CVE-2026-113072 --stage leak
node harness/run-case.mjs CVE-2026-113072 --stage rce

# keep the core dump of a crashing stage for manual gdb work
node harness/run-case.mjs CVE-2026-113280 --stage crash --cores --keep-core
findings/raw/CVE-2026-113280.crash.vulnerable.core.txt   # gdb batch report

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
   describes the exact sequence). The diff is also the specification for every
   later stage: what the fix stops exposing = the leak; what it stops
   re-entering/holding = the corruption to shape.
4. **Stage 1 (crash)** — turn the sequence into `testcase.html`; make the bug
   observable in release with heap shaping and `gdb` breakpoints/watchpoints
   on the patched lines; compare crashes on both builds.
5. **Stage 2 (leak)** — publish what the API must not return, corroborate the
   value in `gdb`, show the patched build returns nothing.
6. **Stage 3 (RCE)** — walk the ladder (shape → primitives → arbitrary R/W →
   chosen `rip` → lab-marker payload), one evidence file per rung.
7. **Differential check** — every stage runs on the vulnerable build and on the
   first patched one; a stage that behaves the same on both is not evidence.

## Limitations (important)

- **No sanitizers, by design.** Chrome for Testing ships `release` builds and
  this lab does not rebuild Chromium. A UAF may never abort by itself; the
  technique is shaping + live `gdb` (see *Debugging with normal tools* and
  `docs/EXPLOITATION.md` §1). `docs/ASAN.md` is kept as optional reference
  only and is not part of the workflow.
- **Stripped binaries.** Chromium frames in a core are addresses. Symbols come
  from the modules that carry them (`objdump -d`, `readelf -Ws`) and from
  offsets relative to the fix diff; `symbol_level=1`/Breakpad symbols are an
  optional local aid, not a requirement.
- **Driver/hardware bugs.** CVE-2026-113341 lives in the Imagination driver;
  without that hardware it cannot be reproduced.
- **Browser-process bugs.** A UAF in the browser process shows up as a CDP
  disconnect, not as `page.on('crash')`; the oracle classifies it as
  `browser-launch-or-connection` (the core dump disambiguates).
- **Timing.** Several cases are races; they run with `iterations` and stress,
  but a "no crash" result **does not prove** the bug is absent — take it to
  `gdb` and break the window open instead of only retrying.
- **Renderer scope.** "RCE" here means controlled execution in the renderer,
  matching the advisories. Defeating Site Isolation/the renderer sandbox is a
  separate scope and is only in scope for CVEs that *are* sandbox bugs.

## Adding a new CVE

```bash
python3 scripts/sync_cves.py --min-severity High --days 30
python3 scripts/find_fixes.py --cve CVE-2026-XXXXX
mkdir cases/CVE-2026-XXXXX   # case.json (with stages) + testcase.html + PoCs
node harness/run-case.mjs CVE-2026-XXXXX --stage crash
```

See [`docs/ADDING_CVES.md`](docs/ADDING_CVES.md).

## References

- Chrome Releases: <https://chromereleases.googleblog.com/>
- Chrome Security (severity guidelines): <https://www.chromium.org/developers/severity-guidelines/>
- Chrome for Testing: <https://googlechromelabs.github.io/chrome-for-testing/>
- NVD: <https://nvd.nist.gov/>

## Disclaimer

Use only in your own, isolated, authorized environment. Do not point the
harness or any PoC at third-party sites, and do not run these PoCs against
browser builds you do not own.

This is an exploitation-research lab: it contains crash, leak and RCE PoCs for
**already-patched** CVEs, built to verify fixes and to document exploitability.
It is not a product or a weaponized kit: payloads are lab markers, targets are
the pinned local builds, and no part of it is meant to be deployed against
systems without authorization. Any use to attack systems without authorization
is outside the intended scope and is the responsibility of whoever performs it.
