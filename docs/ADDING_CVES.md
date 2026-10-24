# Adding a CVE to the lab

## 1. Inventory

```bash
python3 scripts/sync_cves.py --min-severity High --days 30
```

Generates `data/cves.json` from the official feed. Fields: `cve`, `severity`,
`component`, `bug_id`, `fixed_version`, `release_date`, `advisory`.

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
├── case.json       # builds, flags, timeout, status
├── testcase.html   # HTML/JS that exercises the vulnerable path
└── README.md       # root cause, relevant diff, result
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
  "expectation": "what should be observed"
}
```

Statuses:

| status | meaning |
|--------|---------|
| `behavioral` | compares observable behavior, not crashes |
| `stress` | looks for crashes through repetition/races |
| `blocked` | missing an ingredient (network, SW, timing) |
| `not-reproducible` | depends on hardware/driver |

## 5. Testcase rules

- Publish the verdict in `window.__LAB_RESULT` (JSON-serializable).
- Do not block the main thread indefinitely; use a `setTimeout` fallback.
- No external network: everything must be served from `cases/<CVE>/` (the
  harness starts a static server on `127.0.0.1`).
- If you need a secure context, `127.0.0.1` already is one.

## 6. Run

```bash
node harness/run-case.mjs CVE-2026-XXXXX
node harness/run-case.mjs CVE-2026-XXXXX --headed   # real caret/paint
```

Results: `findings/CVE-2026-XXXXX.json` (comparison) and
`findings/raw/<CVE>.<vulnerable|fixed>.json` (raw oracle output).

## 7. ASAN builds (optional, for real UAFs)

Chrome for Testing does not ship sanitizer builds. For reliable detection:

```bash
# requirements: depot_tools, ~100 GB free
fetch chromium
cd src && gn gen out/asan --args='is_debug=false is_asan=true is_component_build=false'
autoninja -C out/asan chrome
```

Then point the case at that binary:

```json
{ "browser": "/path/to/src/out/asan/chrome" }
```

See [`ASAN.md`](ASAN.md) for the full procedure.
