# Chromium ASAN build

Chrome for Testing ships `release` builds: a UAF may never abort. To actually
characterize the bugs in the exploitability report you need a build with
AddressSanitizer.

## Realistic cost

| Resource | Estimate |
|----------|----------|
| Disk | 100–150 GB (checkout + out/asan) |
| RAM | 16 GB minimum; 32 GB recommended for linking |
| Time | 2–6 h depending on CPU (first build) |
| Network | ~50–80 GB of downloads |

This is not something you can do "in a minute". Plan for it.

## Automated

```bash
chmod +x scripts/setup_asan.sh
JOBS=8 ./scripts/setup_asan.sh 155.0.8059.84
```

For the CVE-2026-110922 regression test, build the test target instead:

```bash
TARGET=content_browsertests JOBS=8 ./scripts/setup_asan.sh 155.0.8059.84
```

The script clones `depot_tools`, runs `fetch chromium`, checks out the release
tag, runs `gclient sync`, generates `out/asan` with `is_asan=true` and builds.

## Manual

```bash
git clone --depth 1 https://chromium.googlesource.com/chromium/tools/depot_tools.git
export PATH="$PWD/depot_tools:$PATH"

fetch --nohooks --no-history chromium
cd src
git fetch origin refs/tags/155.0.8059.84:refs/tags/155.0.8059.84 --depth 1
git checkout 155.0.8059.84
gclient sync -D --with_branch_heads --with_tags

gn gen out/asan --args='
  is_debug=false
  is_official_build=false
  is_asan=true
  is_component_build=false
  symbol_level=1
  blink_symbol_level=1
'

autoninja -C out/asan chrome
```

## Run a case against the ASAN build

Edit `cases/<CVE>/case.json` and add the absolute path:

```json
{ "browser": "/home/you/chromium/src/out/asan/chrome" }
```

Or pass the paths on the CLI:

```bash
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1 \
  node harness/run-case.mjs CVE-2026-113271 \
  --vuln /home/you/chromium/src/out/asan/chrome \
  --fixed builds/156.0.8078.47/chrome-linux64/chrome
```

> The ASAN build already contains the fix if you build 156. To compare
> properly, build the **vulnerable** version with ASAN and run the case against
> it (`--fixed` can point at the patched release build; what matters is seeing
> the ASAN report on the vulnerable one).

## What to look for in the report

```
ERROR: AddressSanitizer: heap-use-after-free on address 0x...
READ of size 8 at 0x... thread T0
    #0 ... AXObjectCacheImpl::RemoveSubtreeInternal()
freed by thread T0 here:
    #0 ... operator delete
    #1 ... AXObject::...
previously allocated by thread T0 here:
    #0 ... operator new
```

Questions it answers:

1. Is it a real UAF or just an inconsistent state?
2. Type and size of the freed object (key for PartitionAlloc).
3. Is the free stack deterministic or timing-dependent?
4. Is the access a read or a write?

With that data you update `findings/EXPLOITABILITY.md` with facts instead of
speculation.

## Alternative for the WebRTC race

CVE-2026-113303 is a data race: the right sanitizer is **TSAN**
(`is_tsan=true`), not ASAN. Build `out/tsan` with the same steps, replacing
`is_asan=true` with `is_tsan=true`.

## Reproducing CVE-2026-110922 deterministically

The browser-process UAF cannot be scheduled from web content (see
`cases/CVE-2026-110922/README.md`). The deterministic reproduction is the
regression test that ships with the patch:

```bash
autoninja -C out/asan content_browsertests
out/asan/content_browsertests \
  --gtest_filter='*EvictBackForwardCacheDuringPrerenderActivationCheck*'
```

With an ASAN build the use-after-free is reported with the free/alloc stacks;
without a fix it aborts, with the fix it passes.

## Notes

- `is_component_build=false` is required for ASAN on Linux.
- If linking runs out of memory, lower `symbol_level` to 0 or set
  `use_thin_lto=false`.
- Do not run the ASAN binary with `--no-sandbox` outside the lab container.
