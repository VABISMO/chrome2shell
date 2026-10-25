# Adding a CVE to the lab

## 1. Inventory

```bash
# full High/Critical inventory since a date (paged feed)
python3 scripts/sync_cves.py --since 2023-10-01 --min-severity High

# RCE-relevant subset (memory-safety bug with a plausible code-exec path,
# plus everything exploited in the wild)
python3 scripts/sync_cves.py --since 2023-10-01 --min-severity High \
  --rce-only --out data/rce_cves.json

# highest-priority backlog: Critical memory-safety + all in-the-wild CVEs
python3 scripts/sync_cves.py --since 2023-10-01 --min-severity High \
  --priority --out data/rce_priority.json
```

The script pages the official *Stable updates* feed (`start-index`) until it
crosses `--since`, then writes `data/cves.json`. Fields: `cve`, `severity`,
`component`, `bug_id`, `fixed_version`, `release_date`, `advisory`, plus
`rce_relevance` (`high`/`medium`/`low`), `rce_rationale` and
`exploited_in_wild`.

Classification is a heuristic on the advisory text: the bug class comes from
the phrase before "in" ("Use after free in Prerender") and the component from
the phrase after. Plain out-of-bounds *reads* and non-memory-safety classes are
`low`; the `--rce-only` view drops them. `--offline` reuses the cached feed.

Only work on CVEs with a plausible browser RCE path. Policy bypasses, UI
spoofing, info leaks and DoS are catalogued in `data/cves.json` but are out of
scope for cases.

## 2. Locate the patch

```bash
python3 scripts/find_fixes.py --cve CVE-2026-XXXXX
```

- Searches `repo:<repo> <bug_id>` through the GitHub commit search API.
- Repositories tried in order: `chromium/chromium`, `google/skia`,
  `google/dawn`, `google/angle`.
- Stores the commit in `data/fixes.json` and the diff in
  `patches/<CVE>.patch`.

If nothing shows up, the fix may live in another repo (e.g. `google/webrtc`)
or may not be public yet. Add the repo to `REPOS` in the script.

## 3. Read the root cause

Open the `.patch`. Security patches usually include a regression test whose
name and comments describe the exact sequence. That test is the best PoC
specification you will get.

## 4. Create the case

```
cases/CVE-2026-XXXXX/
├── case.json       # builds, flags, timeout, and stages.<stage> = {entry, status}
├── testcase.html   # stage 1: HTML/JS that exercises the vulnerable path
├── poc-leak.html   # stage 2: leak/exposure PoC (created when the stage starts)
├── poc-rce.html    # stage 3: RCE PoC (created when the stage starts)
└── README.md       # root cause, relevant diff, stage status
```

`case.json`:

```json
{
  "cve": "CVE-2026-XXXXX",
  "name": "short description",
  "vulnerable": "155.0.8059.84",
  "fixed": "156.0.8078.47",
  "entry": "testcase.html",
  "timeoutMs": 30000,
  "iterations": 2,
  "flags": ["--force-renderer-accessibility"],
  "status": "stress",
  "expectation": "what should be observed",
  "stages": {
    "crash": { "entry": "testcase.html", "status": "pending" },
    "leak":  { "entry": "poc-leak.html", "status": "pending" },
    "rce":   { "entry": "poc-rce.html",  "status": "pending" }
  }
}
```

Statuses:

| status | meaning |
|--------|---------|
| `behavioral` | compares observable behavior, not crashes |
| `stress` | looks for crashes through repetition/races |
| `blocked` | missing an ingredient (network, SW, timing) |
| `not-reproducible` | depends on hardware/driver |

Stage statuses (inside `stages`, and mirrored in `findings/STAGES.md`):
`pending` (not started), `in-progress` (path exercised, no evidence yet),
`partial` (evidence exists, short of the exit criteria), `done` (exit criteria
met **and** the patched build fails the same PoC), `blocked`.

## 5. Testcase rules

- Publish the verdict in `window.__LAB_RESULT` (JSON-serializable,
  deterministic: no timestamps or run-dependent values — the harness compares
  it across builds).
- Do not block the main thread indefinitely; use a `setTimeout` fallback.
- No external network: everything must be served from `cases/<CVE>/` (the
  harness starts a static server on `127.0.0.1`).
- If you need a secure context, `127.0.0.1` already is one.
- Each stage has its own entry file and its own evidence: the PoC of a stage
  must produce its effect on the vulnerable build and **fail on the patched
  one**. If it behaves the same on both, it is not stage evidence.

## 6. Run

```bash
node harness/run-case.mjs CVE-2026-XXXXX                    # stage 1 (crash)
node harness/run-case.mjs CVE-2026-XXXXX --stage leak       # stage 2
node harness/run-case.mjs CVE-2026-XXXXX --stage rce        # stage 3
node harness/run-case.mjs CVE-2026-XXXXX --headed           # real caret/paint
node harness/run-case.mjs CVE-2026-XXXXX --cores --keep-core  # keep the core
```

Results: `findings/CVE-2026-XXXXX.json` (comparison) and
`findings/raw/<CVE>.<stage>.<vulnerable|fixed>.json` (raw oracle output, plus
`*.core.txt` when `--cores` is used).

If the bug needs prerendering, service workers, or a stalled response, the
static file server is not enough. See `harness/repro-110922.mjs` (dynamic
server) and `harness/selfdrive-110922.mjs` (no CDP) as templates. Note that any
DevTools/CDP session without tab-target support disables prerendering
(`kPrerenderingDisabledByDevTools`), so prerender bugs must be driven without
Playwright.

## 7. Stage 1 without a crash (normal debug tools)

A release build often will not fault for a real UAF — that is not a failed
case, it is a case that needs `gdb`. In increasing depth, all without
sanitizers (full techniques: [`EXPLOITATION.md`](EXPLOITATION.md) §1):

1. **Core + gdb batch.** The harness enables kernel core dumps and runs gdb in
   batch mode over the crash. See [`GDB.md`](GDB.md).
2. **Heap shaping.** Reclaim the freed slot with a controlled object of the
   same size and show the observable corruption from JS (length/elements
   changed) — stage-1 evidence without a fault.
3. **Live breakpoints and watchpoints.** Break on the exact lines the patch
   changes (addresses via `objdump -d`/`info proc mappings`), or `watch` the
   dangling slot; drive the regression test's sequence under gdb.

`docs/ASAN.md` exists as optional reference only; sanitizer builds are **not**
part of this lab's workflow.
