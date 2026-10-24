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

The last two stable releases (October 15 and 20, 2026) contain **7 CVEs rated
`Critical`** by the Chrome team:

| CVE | Component | Type | Bug ID | Fix commit | Reproducible |
|-----|-----------|------|--------|-----------|--------------|
| CVE-2026-110922 | Prerender | UAF (browser) | 568719351 | `d50992ebe4` | ⚠️ needs BFCache+SW |
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

**Reality check on reproduction:** 6 of the 7 are memory corruptions that do not
reliably abort in `release` builds (no ASAN or DCHECKs). The lab is meant to
(1) confirm the vulnerable path, (2) compare vulnerable vs. patched builds and
(3) serve as a base for an ASAN build. Per-CVE details are in
[`findings/RESULTS.md`](findings/RESULTS.md) and
[`findings/EXPLOITABILITY.md`](findings/EXPLOITABILITY.md).

---

## Layout

```
chrome-cve-lab/
├── data/
│   ├── cves.json          # inventory generated from the official feed
│   ├── fixes.json         # CVE -> fix commit + patch
│   └── cache/feed.json    # feed snapshot (--offline mode)
├── scripts/
│   ├── sync_cves.py       # Chrome Releases RSS -> data/cves.json
│   ├── find_fixes.py      # bug ID -> fix commit -> patches/<CVE>.patch
│   ├── fetch_chrome.py    # download an exact Chrome for Testing version
│   └── setup_asan.sh      # Chromium ASAN build (multi-hour, optional)
├── harness/
│   ├── oracle.mjs         # load a URL and detect crashes (renderer/browser)
│   ├── run-case.mjs       # run a case on vulnerable vs. patched builds
│   └── repro-110922.mjs   # CVE-2026-110922 reproducer (dynamic server)
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
- [`docs/ASAN.md`](docs/ASAN.md) — sanitizer build to characterize the UAFs
  (the real next step).

## Requirements

- Node.js ≥ 20 and `npm install` (only `playwright-core`, no bundled browsers).
- Python 3.10+.
- ~400 MB of disk per Chrome for Testing build.
- Docker is not required. The Chrome binary runs directly.

## Usage

```bash
npm install

# 1. critical CVE inventory (last 60 days)
python3 scripts/sync_cves.py --min-severity Critical --days 60

# 2. locate patches (bug ID -> commit -> patch)
python3 scripts/find_fixes.py

# 3. download the vulnerable build and the first patched one
python3 scripts/fetch_chrome.py 155.0.8059.84 156.0.8078.47

# 4. run one case (or all of them)
node harness/run-case.mjs CVE-2026-113072
node harness/run-case.mjs --all
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
